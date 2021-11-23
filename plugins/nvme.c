/*
 * vfio nvme engine
 *
 * this engine read/write nvme namespace by vfio.
 */

#include "fio.h"
#include "optgroup.h"

#include "libvfio/include/nvme.h"
#include <poll.h>
#include <stdlib.h>

struct nvme_task {
  struct iovec iov;
  struct io_u *io_u;
  struct fio_nvme *fio_nvme;
  struct flist_head entry;
};

struct fio_nvme {
  struct nvme_device *device;
  struct nvme_info *info; // parent
  int block_size;
  uint64_t num_blocks;

  unsigned int queued;
  unsigned int events;
  unsigned long queued_bytes;

  struct flist_head tasks;
};

struct nvme_info {
  struct fio_nvme **nvmes;
  int nr_nvmes;

  struct nvme_task **cpl_tasks;
  int nr_events;
};

struct nvme_options {
  void *pad;
  unsigned int io_num_queue;
};

static struct fio_option options[] = {
    {
        .name = "io_num_queue",
        .lname = "Nvme io queue number",
        .type = FIO_OPT_STR_SET,
        .off1 = offsetof(struct nvme_options, io_num_queue),
        .help = "Set the io queue number",
        .category = FIO_OPT_C_ENGINE,
        .group = FIO_OPT_G_INVALID,
    },
    {
        .name = NULL,
    },
};

static int fio_nvme_setup_one(struct thread_data *td,
                              struct nvme_info *nvme_info, struct fio_file *f,
                              int d_idx) {
  struct fio_nvme *fio_nvme = NULL;
  struct nvme_task *task;
  int i;
  fio_nvme = calloc(1, sizeof(*fio_nvme));
  fio_nvme->device = nvme_init(f->file_name);
  fio_nvme->info = nvme_info;
  nvme_info->nvmes[d_idx] = fio_nvme;

  fio_nvme->block_size = nvme_get_blocksize(fio_nvme->device);
  fio_nvme->num_blocks = nvme_get_numblocks(fio_nvme->device);

  f->real_file_size = fio_nvme->num_blocks * fio_nvme->block_size;
  f->engine_data = fio_nvme;
  printf("pid: %d block size: %d num blocks: %" PRIu64 "\n", getpid(),
         fio_nvme->block_size, fio_nvme->num_blocks);
  // memset(fio_nvme->device->qps[1]->sq.queue + 64, 0xfe, 64);
  INIT_FLIST_HEAD(&fio_nvme->tasks);
  for (i = 0; i < td->o.iodepth; ++i) {
    task = calloc(1, sizeof(*task));
    INIT_FLIST_HEAD(&task->entry);
    flist_add_tail(&task->entry, &fio_nvme->tasks);
  }
  return 0;
}

static int fio_nvme_init(struct thread_data *td) {
  struct nvme_info *nvme_info;
  int ret = 0;
  struct fio_file *f;
  int i;

  nvme_info = malloc(sizeof(struct nvme_info));
  nvme_info->nr_nvmes = td->o.nr_files;
  nvme_info->nvmes = calloc(nvme_info->nr_nvmes, sizeof(struct fio_nvme *));
  nvme_info->cpl_tasks = malloc(td->o.iodepth * sizeof(struct nvme_task));

  td->io_ops_data = nvme_info;

  for_each_file(td, f, i) {
    ret = fio_nvme_setup_one(td, nvme_info, f, i);
    if (ret < 0)
      break;
  }

  return ret;
}

static void nvme_cb(void *opaque, int status) {
  struct nvme_task *nvme_task = (struct nvme_task *)opaque;
  struct fio_nvme *fio_nvme = nvme_task->fio_nvme;
  struct nvme_info *nvme_info = fio_nvme->info;
  struct io_u *io_u = nvme_task->io_u;

  if (status == 0) {
    io_u->error = 0;
  } else {
    log_err("nvme: request failed with error %d.\n", status);
    io_u->error = 1;
    io_u->resid = io_u->xfer_buflen;
  }

  nvme_info->cpl_tasks[nvme_info->nr_events++] = nvme_task;
}

static enum fio_q_status fio_nvme_queue(struct thread_data *td,
                                        struct io_u *io_u) {
  struct fio_nvme *fio_nvme = io_u->file->engine_data;
  struct nvme_task *task;
  int q_idx;
  if (fio_nvme->queued == td->o.iodepth) {
    printf("fio_nvme: reach max depth %d empty: %d\n", fio_nvme->queued,
           flist_empty(&fio_nvme->tasks));
    return FIO_Q_BUSY;
  }

  task = flist_first_entry(&fio_nvme->tasks, struct nvme_task, entry);
  flist_del(&task->entry);

  task->fio_nvme = fio_nvme;
  task->io_u = io_u;
  task->iov.iov_len = io_u->xfer_buflen;
  task->iov.iov_base = io_u->xfer_buf;
  q_idx = fio_nvme->queued % (fio_nvme->device->qp_cnt - 1) + 1;
  // printf("pid: %d io_u offset: %llu len: %llu queued: %d\n", getpid(),
  //        io_u->offset, io_u->xfer_buflen, fio_nvme->queued);
  fio_nvme->queued++;
  nvme_submit_io(fio_nvme->device, q_idx, io_u->offset, io_u->xfer_buflen,
                 &task->iov, 1, io_u->ddir == DDIR_WRITE, 0, nvme_cb, task);
  return FIO_Q_QUEUED;
}

// return the io done num, then the .event will get the idx to get the io_u.
static int fio_nvme_getevents(struct thread_data *td, unsigned int min,
                              unsigned int max, const struct timespec *t) {
  struct nvme_info *nvme_info = td->io_ops_data;
  int nr = 0;
  nvme_info->nr_events = 0;

  while (nvme_info->nr_events < min) {
    for (int i = 0; i < nvme_info->nr_nvmes; i++) {
      // printf("min: %d, nvme_info->nr_events: %d nr :%d device: %d \n", min,
      //        nvme_info->nr_events, nr, i);
      nr += nvme_poll(nvme_info->nvmes[i]->device);
    }
  }
  if (nr != nvme_info->nr_events) {
    printf("BUG\n");
    exit(0);
  }
  return nr;
}

static struct io_u *fio_nvme_event(struct thread_data *td, int event) {
  struct nvme_info *nvme_info = (struct nvme_info *)td->io_ops_data;
  struct nvme_task *task = nvme_info->cpl_tasks[event];
  task->fio_nvme->queued--;
  flist_add_tail(&task->entry, &task->fio_nvme->tasks);
  return task->io_u;
}

static int fio_nvme_open_file(struct thread_data *td, struct fio_file *f) {
  return 0;
}

static int fio_nvme_close_file(struct thread_data *td, struct fio_file *f) {
  return 0;
}

static int fio_nvme_prep(struct thread_data *td, struct io_u *io_u) {
  // printf("pid %d: prep...\n", getpid());
  return 0;
}

// static int fio_nvme_commit(struct thread_data *td)
// {
// 	if (!ld->queued)
// 		return 0;
// }

// In the fork child process.
// static 	int fio_nvme_init (struct thread_data *) {
//   printf("pid %d: init ...\n", getpid());
//   return 0;
// }

FIO_STATIC struct ioengine_ops ioengine = {
    .name = "nvme",
    .version = FIO_IOOPS_VERSION,
    .flags = FIO_SYNCIO | FIO_DISKLESSIO | FIO_NODISKUTIL,
    // .setup = fio_nvme_setup,
    .init = fio_nvme_init,
    .queue = fio_nvme_queue,
    // .commit = fio_nvme_commit,
    .getevents = fio_nvme_getevents,
    .event = fio_nvme_event,
    .open_file = fio_nvme_open_file,
    .close_file = fio_nvme_close_file,
    .prep = fio_nvme_prep,
    .option_struct_size = sizeof(struct nvme_options),
    .options = options,
};

static void fio_init fio_nvme_register(void) { register_ioengine(&ioengine); }

static void fio_exit fio_nvme_unregister(void) {
  unregister_ioengine(&ioengine);
}
