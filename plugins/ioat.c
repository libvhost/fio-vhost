/*
 * vfio ioat/pmem engine
 *
 * this engine read/write pmem by vfio.
 */

#include "fio.h"
#include "optgroup.h"

#include "libvfio/include/ioat.h"
#include "libvfio/include/vfio-helper.h"
#include <poll.h>
#include <stdlib.h>

#define DUMMY_SIZE 256 * PAGE_SIZE
struct ioat_task {
  struct iovec iov;
  struct io_u *io_u;
  struct fio_ioat *fio_ioat;
  struct flist_head entry;
};

struct fio_ioat {
  struct propig_ioat_chan *ioat;
  struct ioat_info *info; // parent

  unsigned int queued;
  unsigned int events;
  unsigned long queued_bytes;

  struct flist_head tasks;
  char *dummy_buffer;
};

struct ioat_info {
  struct fio_ioat **ioats;
  int nr_ioats;

  struct ioat_task **cpl_tasks;
  int nr_events;
};

struct ioat_options {
  void *pad;
  unsigned int io_num_queue;
};

static struct fio_option options[] = {
    {
        .name = "io_num_queue",
        .lname = "ioat io queue number",
        .type = FIO_OPT_STR_SET,
        .off1 = offsetof(struct ioat_options, io_num_queue),
        .help = "Set the io queue number",
        .category = FIO_OPT_C_ENGINE,
        .group = FIO_OPT_G_INVALID,
    },
    {
        .name = NULL,
    },
};

static int fio_ioat_setup_one(struct thread_data *td,
                              struct ioat_info *ioat_info, struct fio_file *f,
                              int d_idx) {
  struct fio_ioat *fio_ioat = NULL;
  struct ioat_task *task;
  int i;
  fio_ioat = calloc(1, sizeof(*fio_ioat));
  fio_ioat->ioat = ioat_channel_init(f->file_name);
  if (posix_memalign((void **)&fio_ioat->dummy_buffer, PAGE_SIZE, DUMMY_SIZE)) {
    return -1;
  }
  fio_ioat->info = ioat_info;
  ioat_info->ioats[d_idx] = fio_ioat;
  f->engine_data = fio_ioat;
  INIT_FLIST_HEAD(&fio_ioat->tasks);
  for (i = 0; i < td->o.iodepth; ++i) {
    task = calloc(1, sizeof(*task));
    INIT_FLIST_HEAD(&task->entry);
    flist_add_tail(&task->entry, &fio_ioat->tasks);
  }
  // Buffer memory alignment.
  td->o.mem_align = 4096;
  return 0;
}

static int fio_ioat_init(struct thread_data *td) {
  struct ioat_info *ioat_info;
  int ret = 0;
  struct fio_file *f;
  int i;

  ioat_info = malloc(sizeof(struct ioat_info));
  ioat_info->nr_ioats = td->o.nr_files;
  ioat_info->ioats = calloc(ioat_info->nr_ioats, sizeof(struct fio_ioat *));
  ioat_info->cpl_tasks = malloc(td->o.iodepth * sizeof(struct ioat_task));

  td->io_ops_data = ioat_info;

  for_each_file(td, f, i) {
    ret = fio_ioat_setup_one(td, ioat_info, f, i);
    if (ret < 0)
      break;
  }

  return ret;
}

static void ioat_cb(void *opaque, int status) {
  struct ioat_task *ioat_task = (struct ioat_task *)opaque;
  struct fio_ioat *fio_ioat = ioat_task->fio_ioat;
  struct ioat_info *ioat_info = fio_ioat->info;
  struct io_u *io_u = ioat_task->io_u;

  if (status == 0) {
    io_u->error = 0;
  } else {
    log_err("ioat: request failed with error %d.\n", status);
    io_u->error = 1;
    io_u->resid = io_u->xfer_buflen;
  }

  ioat_info->cpl_tasks[ioat_info->nr_events++] = ioat_task;
}

static enum fio_q_status fio_ioat_queue(struct thread_data *td,
                                        struct io_u *io_u) {
  struct fio_ioat *fio_ioat = io_u->file->engine_data;
  struct ioat_task *task;
  void *dst;
  void *src;

  if (fio_ioat->queued == td->o.iodepth) {
    printf("fio_ioat: reach max depth %d empty: %d\n", fio_ioat->queued,
           flist_empty(&fio_ioat->tasks));
    return FIO_Q_BUSY;
  }

  task = flist_first_entry(&fio_ioat->tasks, struct ioat_task, entry);
  flist_del(&task->entry);

  task->fio_ioat = fio_ioat;
  task->io_u = io_u;
  task->iov.iov_len = io_u->xfer_buflen;
  task->iov.iov_base = io_u->xfer_buf;
  // q_idx = fio_ioat->queued % (fio_ioat->ioat->qp_cnt - 1) + 1;
  // printf("pid: %d io_u offset: %llu len: %llu queued: %d\n", getpid(),
  //        io_u->offset, io_u->xfer_buflen, fio_ioat->queued);
  fio_ioat->queued++;
  if (io_u->ddir == DDIR_WRITE) {
    src = io_u->xfer_buf;
    dst = fio_ioat->dummy_buffer;
  } else {
    src = fio_ioat->dummy_buffer;
    dst = io_u->xfer_buf;
  }

  propig_ioat_submit_copy(fio_ioat->ioat, task, ioat_cb, dst, src,
                          io_u->xfer_buflen);
  return FIO_Q_QUEUED;
}

// return the io done num, then the .event will get the idx to get the io_u.
static int fio_ioat_getevents(struct thread_data *td, unsigned int min,
                              unsigned int max, const struct timespec *t) {
  struct ioat_info *ioat_info = td->io_ops_data;
  int nr = 0;
  ioat_info->nr_events = 0;

  while (ioat_info->nr_events < min) {
    for (int i = 0; i < ioat_info->nr_ioats; i++) {
      // printf("min: %d, ioat_info->nr_events: %d nr :%d device: %d \n", min,
      //        ioat_info->nr_events, nr, i);
      nr += propig_ioat_process_events(ioat_info->ioats[i]->ioat);
    }
  }
  if (nr != ioat_info->nr_events) {
    printf("BUG %d != %d\n", nr, ioat_info->nr_events);
    exit(0);
  }
  return nr;
}

static struct io_u *fio_ioat_event(struct thread_data *td, int event) {
  struct ioat_info *ioat_info = (struct ioat_info *)td->io_ops_data;
  struct ioat_task *task = ioat_info->cpl_tasks[event];
  task->fio_ioat->queued--;
  flist_add_tail(&task->entry, &task->fio_ioat->tasks);
  return task->io_u;
}

static int fio_ioat_open_file(struct thread_data *td, struct fio_file *f) {
  return 0;
}

static int fio_ioat_close_file(struct thread_data *td, struct fio_file *f) {
  return 0;
}

static int fio_ioat_prep(struct thread_data *td, struct io_u *io_u) {
  // printf("pid %d: prep...\n", getpid());
  return 0;
}

static int fio_ioat_post_init(struct thread_data *td) {
  int i;
  int ioat_idx;
  struct fio_ioat *fio_ioat;
  struct ioat_info *ioat_info = td->io_ops_data;
  unsigned int max_bs;
  max_bs = max(td->o.max_bs[DDIR_READ], td->o.max_bs[DDIR_WRITE]);

  for (ioat_idx = 0; ioat_idx < ioat_info->nr_ioats; ++ioat_idx) {
    fio_ioat = ioat_info->ioats[ioat_idx];
    /* register each io_u in the free list */
    for (i = 0; i < td->io_u_freelist.nr; i++) {
      struct io_u *io_u = td->io_u_freelist.io_us[i];
      propig_vfio_dma_map(ioat_get_vfio(fio_ioat->ioat), io_u->buf, max_bs,
                          (uint64_t)io_u->buf);
    }
    propig_vfio_dma_map(ioat_get_vfio(fio_ioat->ioat), fio_ioat->dummy_buffer,
                        DUMMY_SIZE, (uint64_t)fio_ioat->dummy_buffer);
  }

  return 0;
}

FIO_STATIC struct ioengine_ops ioengine = {
    .name = "ioat",
    .version = FIO_IOOPS_VERSION,
    .flags = FIO_SYNCIO | FIO_DISKLESSIO | FIO_NODISKUTIL,
    // .setup = fio_ioat_setup,
    .init = fio_ioat_init,
    .post_init = fio_ioat_post_init,
    .queue = fio_ioat_queue,
    // .commit = fio_ioat_commit,
    .getevents = fio_ioat_getevents,
    .event = fio_ioat_event,
    .open_file = fio_ioat_open_file,
    .close_file = fio_ioat_close_file,
    .prep = fio_ioat_prep,
    .option_struct_size = sizeof(struct ioat_options),
    .options = options,
};

static void fio_init fio_ioat_register(void) { register_ioengine(&ioengine); }

static void fio_exit fio_ioat_unregister(void) {
  unregister_ioengine(&ioengine);
}
