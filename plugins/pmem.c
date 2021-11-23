/*
 * vfio pmem/pmem engine
 *
 * this engine read/write pmem by vfio.
 */

#include "fio.h"
#include "optgroup.h"

#include "libvfio/include/ioat.h"
#include "libvfio/include/vfio-helper.h"

#include <libpmem.h>
#include <poll.h>
#include <stdlib.h>
struct pmem_task {
  struct iovec iov;
  struct io_u *io_u;
  struct fio_pmem *fio_pmem;
  struct flist_head entry;
  int odirect;
};

struct fio_pmem {
  struct propig_ioat_chan **ioats;
  int ioat_cnt;
  char *pmem_addr;
  uint64_t pmem_size;

  struct pmem_info *info; // parent
  unsigned int queued;
  unsigned int events;
  unsigned long queued_bytes;

  struct flist_head tasks;
  char *dummy_buffer;
};

struct pmem_info {
  struct fio_pmem **pmems;
  int nr_pmems;

  struct pmem_task **cpl_tasks;
  int nr_events;
};

struct pmem_options {
  void *pad;
  unsigned int ioat_num;
};

static struct fio_option options[] = {
    {
        .name = "ioat_num",
        .lname = "set the ioat num",
        .type = FIO_OPT_STR_SET,
        .off1 = offsetof(struct pmem_options, ioat_num),
        .help = "Set the io ioat number",
        .category = FIO_OPT_C_ENGINE,
        .group = FIO_OPT_G_INVALID,
    },
    {
        .name = NULL,
    },
};

static int fio_pmem_setup_one(struct thread_data *td,
                              struct pmem_info *pmem_info, struct fio_file *f,
                              int d_idx) {
  struct fio_pmem *fio_pmem = NULL;
  struct pmem_task *task;
  int i;
  int is_pmem;
  struct pmem_options *o;
  o = td->eo;

  fio_pmem = calloc(1, sizeof(*fio_pmem));
  fio_pmem->ioat_cnt = o->ioat_num;
  fio_pmem->ioats = ioat_channel_load(&fio_pmem->ioat_cnt);
  if (fio_pmem->ioats == NULL) {
    printf("no ioat devices\n");
    return -1;
  }

  fio_pmem->pmem_addr = (char *)(pmem_map_file(f->file_name, 0, 0, O_RDWR,
                                               &fio_pmem->pmem_size, &is_pmem));
  if (!fio_pmem->pmem_addr) {
    printf("pmem map file failed: %s\n", strerror(errno));
    return -1;
  }
  if (is_pmem == 0) {
    printf("Open a non pmem device: %s.\n", f->file_name);
    return -1;
  }

  fio_pmem->info = pmem_info;
  pmem_info->pmems[d_idx] = fio_pmem;
  f->engine_data = fio_pmem;
  INIT_FLIST_HEAD(&fio_pmem->tasks);
  for (i = 0; i < td->o.iodepth; ++i) {
    task = calloc(1, sizeof(*task));
    INIT_FLIST_HEAD(&task->entry);
    flist_add_tail(&task->entry, &fio_pmem->tasks);
  }
  // Buffer memory alignment.
  td->o.mem_align = 4096;
  return 0;
}

static int fio_pmem_init(struct thread_data *td) {
  struct pmem_info *pmem_info;
  int ret = 0;
  struct fio_file *f;
  int i;

  pmem_info = calloc(1, sizeof(*pmem_info));
  pmem_info->nr_pmems = td->o.nr_files;
  pmem_info->pmems = calloc(pmem_info->nr_pmems, sizeof(struct fio_pmem *));
  pmem_info->cpl_tasks = malloc(td->o.iodepth * sizeof(struct pmem_task));

  td->io_ops_data = pmem_info;

  for_each_file(td, f, i) {
    ret = fio_pmem_setup_one(td, pmem_info, f, i);
    if (ret < 0)
      break;
  }

  return ret;
}

#define FLUSH_ALIGN ((uintptr_t)64)

static void pmem_clflushopt(const void *addr) {
  asm volatile(".byte 0x66; clflush %0" : "+m"(*(volatile char *)(addr)));
}

#include <emmintrin.h>
static void flush_clflush_nolog(const void *addr, size_t len) {
  uintptr_t uptr;

  /*
   * Loop through cache-line-size (typically 64B) aligned chunks
   * covering the given range.
   */
  for (uptr = (uintptr_t)addr & ~(FLUSH_ALIGN - 1);
       uptr < (uintptr_t)addr + len; uptr += FLUSH_ALIGN)
    _mm_clflush((char *)uptr);
}

static void flush_clflushopt_nolog(const void *addr, size_t len) {
  uintptr_t uptr;

  /*
   * Loop through cache-line-size (typically 64B) aligned chunks
   * covering the given range.
   */
  for (uptr = (uintptr_t)addr & ~(FLUSH_ALIGN - 1);
       uptr < (uintptr_t)addr + len; uptr += FLUSH_ALIGN)
    pmem_clflushopt((char *)uptr);
}

static void pmem_cb(void *opaque, int status) {
  struct pmem_task *pmem_task = (struct pmem_task *)opaque;
  struct fio_pmem *fio_pmem = pmem_task->fio_pmem;
  struct pmem_info *pmem_info = fio_pmem->info;
  struct io_u *io_u = pmem_task->io_u;

  if (status == 0) {
    io_u->error = 0;
  } else {
    log_err("pmem: request failed with error %d.\n", status);
    io_u->error = 1;
    io_u->resid = io_u->xfer_buflen;
  }
  if (io_u->ddir == DDIR_WRITE && pmem_task->odirect) {
    pmem_flush(fio_pmem->pmem_addr + io_u->offset, io_u->xfer_buflen);
  }
  pmem_info->cpl_tasks[pmem_info->nr_events++] = pmem_task;
}

static enum fio_q_status fio_pmem_queue(struct thread_data *td,
                                        struct io_u *io_u) {
  struct fio_pmem *fio_pmem = io_u->file->engine_data;
  struct pmem_task *task;
  void *dst;
  void *src;
  int chan_idx = 0;

  if (fio_pmem->queued == td->o.iodepth) {
    printf("fio_pmem: reach max depth %d empty: %d\n", fio_pmem->queued,
           flist_empty(&fio_pmem->tasks));
    return FIO_Q_BUSY;
  }

  task = flist_first_entry(&fio_pmem->tasks, struct pmem_task, entry);
  flist_del(&task->entry);

  task->fio_pmem = fio_pmem;
  task->io_u = io_u;
  task->iov.iov_len = io_u->xfer_buflen;
  task->iov.iov_base = io_u->xfer_buf;
  task->odirect = td->o.odirect;

  // printf("pid: %d io_u offset: %llu len: %llu queued: %d\n", getpid(),
  //        io_u->offset, io_u->xfer_buflen, fio_pmem->queued);
  fio_pmem->queued++;
  if (io_u->ddir == DDIR_WRITE) {
    src = io_u->xfer_buf;
    dst = fio_pmem->pmem_addr + io_u->offset;
  } else {
    src = fio_pmem->pmem_addr + io_u->offset;
    dst = io_u->xfer_buf;
  }

  chan_idx = fio_pmem->queued % fio_pmem->ioat_cnt;
  propig_ioat_build_copy(fio_pmem->ioats[chan_idx], task, pmem_cb, dst, src,
                         io_u->xfer_buflen);
  return FIO_Q_QUEUED;
}

// return the io done num, then the .event will get the idx to get the io_u.
static int fio_pmem_getevents(struct thread_data *td, unsigned int min,
                              unsigned int max, const struct timespec *t) {
  struct pmem_info *pmem_info = td->io_ops_data;
  int nr = 0;
  struct fio_pmem *fio_pmem;
  uint32_t i = 0;
  uint32_t j;

  pmem_info->nr_events = 0;

  while (pmem_info->nr_events < min) {
    fio_pmem = pmem_info->pmems[(i++) % pmem_info->nr_pmems];
    for (j = 0; j < fio_pmem->ioat_cnt; ++j)
      nr += propig_ioat_process_events(fio_pmem->ioats[j]);
  }
  if (nr != pmem_info->nr_events) {
    printf("BUG %d != %d\n", nr, pmem_info->nr_events);
    exit(0);
  }
  return nr;
}

static struct io_u *fio_pmem_event(struct thread_data *td, int event) {
  struct pmem_info *pmem_info = (struct pmem_info *)td->io_ops_data;
  struct pmem_task *task = pmem_info->cpl_tasks[event];
  task->fio_pmem->queued--;
  flist_add_tail(&task->entry, &task->fio_pmem->tasks);
  return task->io_u;
}

static int fio_pmem_open_file(struct thread_data *td, struct fio_file *f) {
  return 0;
}

static int fio_pmem_close_file(struct thread_data *td, struct fio_file *f) {
  return 0;
}

static int fio_pmem_prep(struct thread_data *td, struct io_u *io_u) {
  return 0;
}

static int fio_pmem_post_init(struct thread_data *td) {
  int i;
  int ioat_idx;
  int pmem_idx;
  struct fio_pmem *fio_pmem;
  struct pmem_info *pmem_info = td->io_ops_data;
  uint64_t max_bs;
  max_bs = max(td->o.max_bs[DDIR_READ], td->o.max_bs[DDIR_WRITE]);

  for (pmem_idx = 0; pmem_idx < pmem_info->nr_pmems; ++pmem_idx) {
    fio_pmem = pmem_info->pmems[pmem_idx];
    for (ioat_idx = 0; ioat_idx < fio_pmem->ioat_cnt; ++ioat_idx) {
      /* register each io_u in the free list */
      for (i = 0; i < td->io_u_freelist.nr; i++) {
        struct io_u *io_u = td->io_u_freelist.io_us[i];
        propig_vfio_dma_map(ioat_get_vfio(fio_pmem->ioats[ioat_idx]), io_u->buf,
                            max_bs, (uint64_t)io_u->buf);
      }
      propig_vfio_dma_map(ioat_get_vfio(fio_pmem->ioats[ioat_idx]),
                          fio_pmem->pmem_addr, fio_pmem->pmem_size,
                          (uint64_t)fio_pmem->pmem_addr);
    }
  }

  return 0;
}

static int fio_pmem_commit(struct thread_data *td) {
  int ioat_idx;
  int pmem_idx;
  struct fio_pmem *fio_pmem;
  struct pmem_info *pmem_info = td->io_ops_data;
  for (pmem_idx = 0; pmem_idx < pmem_info->nr_pmems; ++pmem_idx) {
    fio_pmem = pmem_info->pmems[pmem_idx];
    for (ioat_idx = 0; ioat_idx < fio_pmem->ioat_cnt; ++ioat_idx) {
      propig_ioat_flush(fio_pmem->ioats[ioat_idx]);
    }
  }
  return 0;
}

FIO_STATIC struct ioengine_ops ioengine = {
    .name = "ioat_pmem",
    .version = FIO_IOOPS_VERSION,
    .flags = FIO_SYNCIO | FIO_DISKLESSIO | FIO_NODISKUTIL,
    // .setup = fio_pmem_setup,
    .init = fio_pmem_init,
    .post_init = fio_pmem_post_init,
    .queue = fio_pmem_queue,
    .commit = fio_pmem_commit,
    .getevents = fio_pmem_getevents,
    .event = fio_pmem_event,
    .open_file = fio_pmem_open_file,
    .close_file = fio_pmem_close_file,
    .prep = fio_pmem_prep,
    .option_struct_size = sizeof(struct pmem_options),
    .options = options,
};

static void fio_init fio_pmem_register(void) { register_ioengine(&ioengine); }

static void fio_exit fio_pmem_unregister(void) {
  unregister_ioengine(&ioengine);
}
