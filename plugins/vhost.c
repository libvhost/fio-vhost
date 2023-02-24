/*
 * vhost-user engine
 *
 * this engine read/write vhost-user device.
 */
#include "fio.h"
#include "optgroup.h"

#include "libvhost/include/libvhost.h"
#include <poll.h>
#include <stdlib.h>

struct vhost_task {
  struct iovec iov;
  struct io_u *io_u;
  struct fio_vhost *fio_vhost;
  struct flist_head entry;
};

struct fio_vhost {
  struct libvhost_ctrl *device;
  struct vhost_info *info; // parent
  int block_size;
  uint64_t num_blocks;

  unsigned int queued;
  unsigned int events;
  unsigned long queued_bytes;

  struct flist_head tasks;
};

struct vhost_info {
  struct fio_vhost **vhosts;
  int nr_vhosts;

  struct flist_head cpl_tasks;
  int nr_events;
};

struct vhost_options {
  void *pad;
  unsigned int io_num_queue;
};

static struct fio_option options[] = {
    {
        .name = "io_num_queue",
        .lname = "vhost io queue number",
        .type = FIO_OPT_STR_SET,
        .off1 = offsetof(struct vhost_options, io_num_queue),
        .help = "Set the io queue number",
        .category = FIO_OPT_C_ENGINE,
        .group = FIO_OPT_G_INVALID,
    },
    {
        .name = NULL,
    },
};

static struct libvhost_ctrl *fio_create_ctrl(const char *file) {
  int ret;
  struct libvhost_ctrl *ctrl = libvhost_ctrl_create(file);
  if (!ctrl) {
    goto fail_ctrl;
  }

  if (!libvhost_ctrl_init_memory(ctrl, 1ULL << 30)) {
    printf("init memory failed\n");
    goto fail_ctrl;
  }
  ret = libvhost_ctrl_connect(ctrl);
  if (ret != 0) {
    printf("libvhost_ctrl_connect failed: %d\n", ret);
    goto fail_ctrl;
  }
  ret = libvhost_ctrl_setup(ctrl);
  if (ret != 0) {
    printf("libvhost_ctrl_setup failed: %d\n", ret);
    goto fail_ctrl;
  }

  ret = libvhost_ctrl_add_virtqueue(ctrl, 1024);
  if (ret != 0) {
    printf("libvhost_ctrl_add_virtqueue failed: %d\n", ret);
    goto fail_ctrl;
  }
  return ctrl;

fail_ctrl:
  libvhost_ctrl_destroy(ctrl);
  return NULL;
}

static int fio_vhost_setup(struct thread_data *td) {
  int i;
  struct fio_file *f;
  struct libvhost_ctrl *ctrl;
  int ret;

  if (td->o.nr_files > 1) {
    td_verror(td, EINVAL, "vhost engine only supports one file");
    return -1;
  }

  for_each_file(td, f, i) {
    ctrl = libvhost_ctrl_create(f->file_name);
    if (!ctrl) {
      return -1;
    }
    ret = libvhost_ctrl_connect(ctrl);
    if (ret != 0) {
      printf("libvhost_ctrl_connect failed: %d\n", ret);
      libvhost_ctrl_destroy(ctrl);
      return -1;
    }
    f->real_file_size =
        libvhost_ctrl_get_blocksize(ctrl) * libvhost_ctrl_get_numblocks(ctrl);
    libvhost_ctrl_destroy(ctrl);
    // printf("pid: %d capacity: %" PRIu64 "\n", getpid(), f->real_file_size);
  }
  return 0;
}

static void fio_vhost_cleanup(struct thread_data *td) {
  struct vhost_info *vhost_info = td->io_ops_data;
  int i;
  for (i = 0; i < vhost_info->nr_vhosts; i++) {
    libvhost_ctrl_destroy(vhost_info->vhosts[i]->device);
    while (!flist_empty(&vhost_info->vhosts[i]->tasks)) {
      struct vhost_task *task = flist_first_entry(
          &vhost_info->vhosts[i]->tasks, struct vhost_task, entry);
      flist_del(&task->entry);
      free(task);
    }
    free(vhost_info->vhosts[i]);
  }
  free(vhost_info->vhosts);
  free(vhost_info);
}

static int fio_vhost_init_one(struct thread_data *td,
                              struct vhost_info *vhost_info, struct fio_file *f,
                              int d_idx) {
  struct fio_vhost *fio_vhost = NULL;
  struct vhost_task *task;
  int i;
  fio_vhost = calloc(1, sizeof(*fio_vhost));
  fio_vhost->device = fio_create_ctrl(f->file_name);
  fio_vhost->info = vhost_info;
  vhost_info->vhosts[d_idx] = fio_vhost;

  fio_vhost->block_size = libvhost_ctrl_get_blocksize(fio_vhost->device);
  fio_vhost->num_blocks = libvhost_ctrl_get_numblocks(fio_vhost->device);

  f->real_file_size = fio_vhost->num_blocks * fio_vhost->block_size;
  f->engine_data = fio_vhost;
  INIT_FLIST_HEAD(&fio_vhost->tasks);
  for (i = 0; i < td->o.iodepth; ++i) {
    task = calloc(1, sizeof(*task));
    INIT_FLIST_HEAD(&task->entry);
    flist_add_tail(&task->entry, &fio_vhost->tasks);
  }
  INIT_FLIST_HEAD(&vhost_info->cpl_tasks);
  return 0;
}

static int fio_vhost_init(struct thread_data *td) {
  struct vhost_info *vhost_info;
  int ret = 0;
  struct fio_file *f;
  int i;
  vhost_info = calloc(1, sizeof(struct vhost_info));
  vhost_info->nr_vhosts = td->o.nr_files;
  vhost_info->vhosts =
      calloc(vhost_info->nr_vhosts, sizeof(struct fio_vhost *));
  td->io_ops_data = vhost_info;

  for_each_file(td, f, i) {
    ret = fio_vhost_init_one(td, vhost_info, f, i);
    if (ret < 0) {
      // TODO: cleanup
      break;
    }
  }

  return ret;
}

static void vhost_cb(void *opaque, int status) {
  struct vhost_task *vhost_task = (struct vhost_task *)opaque;
  struct fio_vhost *fio_vhost = vhost_task->fio_vhost;
  struct vhost_info *vhost_info = fio_vhost->info;
  struct io_u *io_u = vhost_task->io_u;

  if (status == 0) {
    io_u->error = 0;
  } else {
    log_err("vhost: request failed with error %d.\n", status);
    io_u->error = 1;
    io_u->resid = io_u->xfer_buflen;
  }

  flist_add_tail(&vhost_task->entry, &vhost_info->cpl_tasks);
}

static enum fio_q_status fio_vhost_queue(struct thread_data *td,
                                         struct io_u *io_u) {
  struct fio_vhost *fio_vhost = io_u->file->engine_data;
  struct vhost_task *task;
  int q_idx;
  if (fio_vhost->queued == td->o.iodepth) {
    printf("fio_vhost: reach max depth %d empty: %d\n", fio_vhost->queued,
           flist_empty(&fio_vhost->tasks));
    return FIO_Q_BUSY;
  }

  task = flist_first_entry(&fio_vhost->tasks, struct vhost_task, entry);
  flist_del(&task->entry);

  task->fio_vhost = fio_vhost;
  task->io_u = io_u;
  task->iov.iov_len = io_u->xfer_buflen;
  task->iov.iov_base = io_u->xfer_buf;
  fio_vhost->queued++;
  libvhost_submit(fio_vhost->device, 0, io_u->offset, &task->iov, 1,
                  io_u->ddir == DDIR_WRITE, task);
  return FIO_Q_QUEUED;
}

// return the io done num, then the .event will get the idx to get the io_u.
static int fio_vhost_getevents(struct thread_data *td, unsigned int min,
                               unsigned int max, const struct timespec *t) {
  struct vhost_info *vhost_info = td->io_ops_data;
  int nr = 0;
  VhostEvent events[256];
  int i;

  vhost_info->nr_events = 0;
  while (nr < min) {
    for (int i = 0; i < vhost_info->nr_vhosts; i++) {
      nr +=
          libvhost_getevents(vhost_info->vhosts[i]->device, 0, 1, &events[nr]);
    }
  }

  for (i = 0; i < nr; i++) {
    vhost_cb(events[i].data, events[i].res);
  }
  return nr;
}

static struct io_u *fio_vhost_event(struct thread_data *td, int event) {
  struct vhost_info *vhost_info = (struct vhost_info *)td->io_ops_data;
  struct vhost_task* task = flist_first_entry(&vhost_info->cpl_tasks, struct vhost_task, entry);
  flist_del(&task->entry);
  task->fio_vhost->queued--;
  flist_add_tail(&task->entry, &task->fio_vhost->tasks);
  return task->io_u;
}

static int fio_vhost_open_file(struct thread_data *td, struct fio_file *f) {
  return 0;
}

static int fio_vhost_close_file(struct thread_data *td, struct fio_file *f) {
  return 0;
}

static int fio_vhost_prep(struct thread_data *td, struct io_u *io_u) {
  // printf("pid %d: prep...\n", getpid());
  return 0;
}

// static int fio_vhost_commit(struct thread_data *td)
// {
// 	if (!ld->queued)
// 		return 0;
// }

// In the fork child process.
// static 	int fio_vhost_init (struct thread_data *) {
//   printf("pid %d: init ...\n", getpid());
//   return 0;
// }

static int fio_vhost_iomem_alloc(struct thread_data *td, size_t total_mem) {
  struct vhost_info *vhost_info = td->io_ops_data;
  struct libvhost_ctrl *ctrl = vhost_info->vhosts[0]->device;
  // printf("fio_vhost_iomem_alloc total_mem: %" PRIu64 "\n", total_mem);
  td->orig_buffer = libvhost_malloc(ctrl, total_mem);
  if (td->orig_buffer == NULL)
    return 1;
  return 0;
}

static void fio_vhost_iomem_free(struct thread_data *td) {
  struct vhost_info *vhost_info = td->io_ops_data;
  struct libvhost_ctrl *ctrl = vhost_info->vhosts[0]->device;
  libvhost_free(ctrl, td->orig_buffer);
}

static struct ioengine_ops ioengine = {
    .name = "vhost",
    .version = FIO_IOOPS_VERSION,
    .flags = FIO_SYNCIO | FIO_DISKLESSIO | FIO_NODISKUTIL,
    .setup = fio_vhost_setup,
    .cleanup = fio_vhost_cleanup,
    .init = fio_vhost_init,
    .queue = fio_vhost_queue,
    .getevents = fio_vhost_getevents,
    .event = fio_vhost_event,
    .open_file = fio_vhost_open_file,
    .close_file = fio_vhost_close_file,
    .prep = fio_vhost_prep,
    .iomem_alloc = fio_vhost_iomem_alloc,
    .iomem_free = fio_vhost_iomem_free,
    .option_struct_size = sizeof(struct vhost_options),
    .options = options,
};

static void fio_init fio_vhost_register(void) { register_ioengine(&ioengine); }

static void fio_exit fio_vhost_unregister(void) {
  unregister_ioengine(&ioengine);
}
