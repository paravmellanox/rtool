#ifndef RES_IOCTL_H
#define RES_IOCTL_H

int rdma_core_get_mr_handles(int fd, int max_count,
			     uint32_t **handles, uint32_t *ret_count);
int rdma_core_destroy_mr_by_handle(int fd, uint32_t handle);

#endif
