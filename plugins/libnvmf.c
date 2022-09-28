/*
 * libnvmf engine
 *
 * this engine read/write libnvmf device.
 */
#include "fio.h"
#include "optgroup.h"

#include "libnvmf/include/libnvmf.h"
#include <poll.h>
#include <stdlib.h>

struct nvmf_task {
  struct iovec iov;
  struct io_u *io_u;
  struct fio_one_ctrl *fio_one_ctrl;
  struct flist_head entry;
  int qid;
  uint64_t offset;
};

struct fio_one_ctrl {
  nvmf_ctrl_t ctrl;
  nvmf_options_t options;
  struct nvmf_info *info;
  int block_size;

  unsigned int queued;
  unsigned int events;
  unsigned long queued_bytes;

  struct flist_head tasks;
};

struct nvmf_info {
  struct fio_one_ctrl **nvmfs;
  int nr_nvmfs;

  struct pollfd *pfds;

  struct flist_head cpl_tasks;
  int nr_events;
};

struct nvmf_options {
  void *pad;
  unsigned int io_queues;
  char *hostnqn;
};

static struct fio_option __options [] = {
    {
        .name = "io_queues",
        .lname = "nvmf io queues",
        .type = FIO_OPT_INT,
        .off1 = offsetof(struct nvmf_options, io_queues),
        .def = "1",
        .help = "Set the io queue number",
        .category = FIO_OPT_C_ENGINE,
        .group = FIO_OPT_G_INVALID,
    },
    {
        .name = "hostnqn",
        .lname = "nvmf hostnqn",
        .type = FIO_OPT_STR_STORE,
        .off1 = offsetof(struct nvmf_options, hostnqn),
        .help = "Set the hostnqn",
        .category = FIO_OPT_C_ENGINE,
        .group = FIO_OPT_G_INVALID,
    },
    {
        .name = NULL,
    },
};

  int ret;
  static struct fio_one_ctrl *fio_ctrl_create(char* hostnqn, const char *file, int io_queues) {
  struct fio_one_ctrl *one = calloc(1, sizeof(*one));
  if (!one) {
    printf("calloc failed\n");
    return NULL;
  }
  one->options = nvmf_default_options(file);
  if (!one->options) {
    printf("nvmf: failed to create options\n");
    goto fail;
  }
  nvmf_options_set_kato(one->options, 100000);
  nvmf_options_set_io_queues(one->options, io_queues);
  nvmf_options_set_hdgst(one->options, 0);
  nvmf_options_set_ddgst(one->options, 0);
  if (hostnqn && strlen(hostnqn) > 0) {
      nvmf_options_set_hostnqn(one->options, hostnqn, strlen(hostnqn));
  }
  one->ctrl = nvmf_ctrl_create(one->options);
  if (!one->ctrl) {
    printf("nvmf_ctrl_create failed\n");
    goto fail_ctrl;
  }
  return one;

fail_ctrl:
  nvmf_options_free(one->options);

fail:
  free(one);
  return NULL;
}

static int fio_one_ctrl_init(struct thread_data *td,
                             struct nvmf_info *nvmf_info, struct fio_file *f,
                             int d_idx) {
  struct fio_one_ctrl *fio_one_ctrl = NULL;
  struct nvmf_task *task;
  uint32_t num_blocks;
  struct nvmf_options *options = td->eo;
  int i;
  fio_one_ctrl = fio_ctrl_create(options->hostnqn, f->file_name, options->io_queues);
  fio_one_ctrl->info = nvmf_info;
  nvmf_info->nvmfs[d_idx] = fio_one_ctrl;

  fio_one_ctrl->block_size = nvmf_ns_lbads(fio_one_ctrl->ctrl);
  num_blocks = nvmf_ns_nsze(fio_one_ctrl->ctrl);

  f->real_file_size = num_blocks * fio_one_ctrl->block_size;
  f->engine_data = fio_one_ctrl;
  INIT_FLIST_HEAD(&fio_one_ctrl->tasks);
  for (i = 0; i < td->o.iodepth; ++i) {
    task = calloc(1, sizeof(*task));
    INIT_FLIST_HEAD(&task->entry);
    flist_add_tail(&task->entry, &fio_one_ctrl->tasks);
  }
  return 0;
}

static int fio_one_ctrl_destroy(struct thread_data *td,
                             struct nvmf_info *nvmf_info, struct fio_file *f,
                             int d_idx) {
  struct fio_one_ctrl *fio_one_ctrl = f->engine_data;
  struct flist_head* node, *tmp;
  struct nvmf_task* task;

  flist_for_each_safe(node, tmp, &fio_one_ctrl->tasks ) {
    flist_del(node);
    task = flist_entry(node, struct nvmf_task, entry);
    free(task);
  }
  nvmf_ctrl_release(fio_one_ctrl->ctrl);
  nvmf_options_free(fio_one_ctrl->options);
  free(fio_one_ctrl);
  return 0;
}

static int fio_ctrl_init(struct thread_data *td) {
  struct nvmf_info *nvmf_info;
  int ret = 0;
  struct fio_file *f;
  int i;
  nvmf_info = calloc(1, sizeof(struct nvmf_info));
  nvmf_info->nr_nvmfs = td->o.nr_files;
  nvmf_info->nvmfs = calloc(nvmf_info->nr_nvmfs, sizeof(struct fio_one_ctrl *));
  nvmf_info->pfds = calloc(nvmf_info->nr_nvmfs, sizeof(struct pollfd));
  INIT_FLIST_HEAD(&nvmf_info->cpl_tasks);
  td->io_ops_data = nvmf_info;

  for_each_file(td, f, i) {
    ret = fio_one_ctrl_init(td, nvmf_info, f, i);
    if (ret < 0) {
      break;
    }
    nvmf_info->pfds[i].fd = nvmf_ctrl_fd(nvmf_info->nvmfs[i]->ctrl);
    nvmf_info->pfds[i].events = POLLIN;
  }
  return ret;
}

static void fio_ctrl_cleanup(struct thread_data *td) {
  int i;
  struct fio_file *f;
  struct nvmf_info* nvmf_info = td->io_ops_data;
  for_each_file(td, f, i) {
    fio_one_ctrl_destroy(td, nvmf_info, f, i);
  }
  free(nvmf_info->nvmfs);
  free(nvmf_info->pfds);
  free(nvmf_info);
}

static int fio_ctrl_setup(struct thread_data *td) {
#if 0
  int i;
  struct fio_file *f;
  for_each_file(td, f, i) {
    // this is a trick to let the fork mode works.
    f->real_file_size = 1ULL << 63;
  }
#endif

  fio_ctrl_init(td);
  fio_ctrl_cleanup(td);
  return 0;
}

static void fio_rw_cb(int status, void *opaque) {
  struct nvmf_task *nvmf_task = (struct nvmf_task *)opaque;
  struct fio_one_ctrl *fio_one_ctrl = nvmf_task->fio_one_ctrl;
  struct nvmf_info *nvmf_info = fio_one_ctrl->info;
  struct io_u *io_u = nvmf_task->io_u;

  if (status == 0) {
    io_u->error = 0;
  } else {
    log_err("nvmf: request failed with error %d.\n", status);
    io_u->error = 1;
    io_u->resid = io_u->xfer_buflen;
  }

  flist_add_tail(&nvmf_task->entry, &nvmf_info->cpl_tasks);
}

static void fio_build_req_op(nvmf_ctrl_t ctrl, struct nvmf_task *req,
                             bool is_write) {
  int ret;

  if (!is_write) {
    ret = nvmf_read_async(ctrl, req->qid, &req->iov, 1, req->offset, 0,
                          fio_rw_cb, req);
  } else {
    ret = nvmf_write_async(ctrl, req->qid, &req->iov, 1, req->offset, 0,
                           fio_rw_cb, req);
  }

  if (ret != 0) {
    printf("ret: %d\n", ret);
    assert(0);
  }
}

static enum fio_q_status fio_ctrl_queue(struct thread_data *td,
                                        struct io_u *io_u) {
  struct fio_one_ctrl *fio_one_ctrl = io_u->file->engine_data;
  struct nvmf_task *task;
  int q_idx;
  struct nvmf_options *opts = (struct nvmf_options *)td->eo;
  int ioqueues = opts->io_queues;
  if (fio_one_ctrl->queued == td->o.iodepth) {
    return FIO_Q_BUSY;
  }

  task = flist_first_entry(&fio_one_ctrl->tasks, struct nvmf_task, entry);
  flist_del(&task->entry);

  task->fio_one_ctrl = fio_one_ctrl;
  task->io_u = io_u;
  task->iov.iov_len = io_u->xfer_buflen;
  task->iov.iov_base = io_u->xfer_buf;
  task->offset = io_u->offset;
  task->qid = random() % ioqueues + 1;
  fio_one_ctrl->queued++;
  // printf("offset: %lu, len: %lu, qid: %d\n", task->offset, task->iov.iov_len, task->qid);
  fio_build_req_op(fio_one_ctrl->ctrl, task, io_u->ddir == DDIR_WRITE);
  return FIO_Q_QUEUED;
}

// return the io done num, then the .event will get the idx to get the io_u.
static int fio_ctrl_getevents(struct thread_data *td, unsigned int min,
                              unsigned int max, const struct timespec *t) {
  struct nvmf_info *nvmf_info = td->io_ops_data;
  int ret = 0;
  int i = 0;

  nvmf_info->nr_events = 0;

  while (nvmf_info->nr_events < min) {
    for(; i < nvmf_info->nr_nvmfs; i++) {
      nvmf_info->pfds[i].revents = 0;
    }
    // timeout = 0 means immediate return, -1 means block.
    ret = poll(nvmf_info->pfds, nvmf_info->nr_nvmfs, -1);
    // return 0 means timeout.
    if (ret < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        continue;
      }
      log_err("nvmf: failed to poll events: %s.\n", strerror(errno));
      break;
    }

    for (int i = 0; i < nvmf_info->nr_nvmfs; i++) {
      nvmf_info->nr_events += nvmf_ctrl_process(nvmf_info->nvmfs[i]->ctrl);
    }
  }

  return ret < 0 ? ret : nvmf_info->nr_events;
}

static struct io_u *fio_ctrl_event(struct thread_data *td, int event) {
  struct nvmf_info *nvmf_info = (struct nvmf_info *)td->io_ops_data;
  struct nvmf_task *task;
  task = flist_first_entry(&nvmf_info->cpl_tasks, struct nvmf_task, entry);
  flist_del(&task->entry);

  flist_add_tail(&task->entry, &task->fio_one_ctrl->tasks);
  task->fio_one_ctrl->queued--;
  return task->io_u;
}

static int fio_ctrl_open_file(struct thread_data *td, struct fio_file *f) {
  return 0;
}

static int fio_ctrl_close_file(struct thread_data *td, struct fio_file *f) {
  return 0;
}

static int fio_ctrl_prep(struct thread_data *td, struct io_u *io_u) {
  return 0;
}

static struct ioengine_ops ioengine = {
    .name = "nvmf",
    .version = FIO_IOOPS_VERSION,
    .flags = FIO_SYNCIO | FIO_DISKLESSIO | FIO_NODISKUTIL,
    .setup = fio_ctrl_setup,
    .cleanup = fio_ctrl_cleanup,
    .init = fio_ctrl_init,
    .queue = fio_ctrl_queue,
    .getevents = fio_ctrl_getevents,
    .event = fio_ctrl_event,
    .open_file = fio_ctrl_open_file,
    .close_file = fio_ctrl_close_file,
    .prep = fio_ctrl_prep,
    .option_struct_size = sizeof(struct nvmf_options),
    .options = __options,
};

static void fio_init fio_ctrl_register(void) { register_ioengine(&ioengine); }

static void fio_exit fio_ctrl_unregister(void) {
  unregister_ioengine(&ioengine);
}
