/*
 *  rdma_mr lat -- simple memory registration latency measuring tool
 *
 *  Copyright (c) 2017, Mellanox Technologies. All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef VERSION
#define VERSION "0.1"
#endif

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <hugetlbfs.h>
#include <sys/time.h>
#include <malloc.h>
#include <inttypes.h>
#include <infiniband/verbs.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/capability.h>

#include "options.h"

struct run_ctx {
	struct ibv_context *context;
	struct ibv_pd *pd;
	struct ibv_mr **mr_list;
	char *ibdev_name;
	uint64_t size;
	uint64_t page_size;
	uint64_t align;
	uint64_t rlimit;
	void *buf;
	int access_flags;

	int huge;
	int odp;
	int lock_memory;
	int count;
	int write_pattern;
	int drop_ipc_lock_cap;
	char pattern;
};

#define HUGE_PAGE_KPATH "/proc/sys/vm/nr_hugepages"

static void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("%s\n", argv0);
	printf("Options:\n");
	printf("  -d, --ibdev=<ibdev>      use IB device <dev> (default first device found)\n");
	printf("  -s --size=<size>         size of mr in bytes (default 4096)\n");
	printf("  -l --align=<align_size>  align memory allocation to this size\n");
	printf("  -c --count=<count>       number of memory regions to register\n");
	printf("  -r --rlimit=<bytes>      memory resource hard limit in bytes\n");
	printf("  -u --huge                use huge pages\n");
	printf("  -o --odp                 use ODP registration\n");
	printf("  -L --lock                lock memory before registration\n");
	printf("  -D --drop_ipc_lock       drop ipc lock capability before registration\n");
	printf("  -h                       display this help message\n");
	printf("  -v                       display program version\n");
}

void version(const char *argv0)
{
	printf("%s %s\n", argv0, VERSION);
}

void parse_options(struct run_ctx *ctx, int argc, char **argv)
{
	int opt;
	static struct option long_options[] = {
		{ .name = "ib-dev",   .has_arg = 1, .val = 'd' },
		{ .name = "size",     .has_arg = 1, .val = 's' },
		{ .name = "align",    .has_arg = 1, .val = 'l' },
		{ .name = "pattern",  .has_arg = 1, .val = 'p' },
		{ .name = "rlimit",   .has_arg = 1, .val = 'r' },
		{ .name = "count",    .has_arg = 1, .val = 'c' },
		{ .name = "huge",     .has_arg = 0, .val = 'u' },
		{ .name = "odp",      .has_arg = 0, .val = 'o' },
		{ .name = "lock",     .has_arg = 0, .val = 'L' },
		{ .name = "drop_ipc", .has_arg = 0, .val = 'D' },
		{ .name = NULL }
	};

	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}

	while ((opt = getopt_long(argc, argv, "hv:d:p:r:s:c:l:uoLD", long_options, NULL)) != -1) {
		switch (opt) {
		case 'v':
			version(argv[0]);
			exit(0);
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'd':
			ctx->ibdev_name = strdupa(optarg);
			break;
		case 's':
			ctx->size = parse_size(optarg);
			break;
		case 'l':
			ctx->align = parse_size(optarg);
			break;
		case 'c':
			ctx->count = parse_size(optarg);
			break;
		case 'r':
			ctx->rlimit = parse_size(optarg);
			break;
		case 'p':
			ctx->write_pattern = 1;
			ctx->pattern = *((char*)optarg);
			break;
		case 'u':
			ctx->huge = 1;
			break;
		case 'o':
			ctx->odp = 1;
			break;
		case 'L':
			ctx->lock_memory = 1;
			break;
		case 'D':
			ctx->drop_ipc_lock_cap = 1;
			break;
		}
	}
}

struct statistics {
	long long start, finish, load_time;
	long long min, max;
};

static void start_statistics(struct statistics *s, unsigned long long start)
{
	memset(s, 0, sizeof(*s));
	s->min = LLONG_MAX;
	s->max = LLONG_MIN;
	s->start = start;
}

static void finish_statistics(struct statistics *s,
			      unsigned long long finish)
{
	s->finish = finish;
	s->load_time = finish - s->start;
}

static int config_hugetlb_pages(uint64_t num_hpages)
{
	char hpages_str[128] = {0};
	size_t s;
	int err = 0;
	int fd;

	fd = open(HUGE_PAGE_KPATH, O_RDWR, 0);
	if (fd < 0)
		return fd;
	sprintf(hpages_str, "%ld", num_hpages);
	s = write(fd, hpages_str, strlen(hpages_str));
	if (s != strlen(hpages_str))
		err = -EINVAL;

	close(fd);
	return err;
}

static void reset_huge_tlb_pages(uint64_t num_pages)
{
	config_hugetlb_pages(num_pages);
}

static int config_hugetlb_kernel(struct run_ctx *ctx)
{
	long hpage_size = gethugepagesize();
	uint64_t num_hpages;

	if (hpage_size == 0)
		return -EINVAL;

	num_hpages = ctx->size / hpage_size;
	if (num_hpages == 0)
		num_hpages = 1;

	return config_hugetlb_pages(num_hpages);
}

static int alloc_mem(struct run_ctx *ctx)
{
	int err = 0;

	if (ctx->huge) {
		err = config_hugetlb_kernel(ctx);
		if (err) {
			printf("fail to configure hugetlb\n");
			err = -EINVAL;
			return err;
		}
		ctx->buf = get_hugepage_region(ctx->size, GHR_STRICT | GHR_COLOR);
		if (!ctx->buf) {
			perror("mmap");
			err = -ENOMEM;
			return err;
		}
	} else {
		ctx->buf = memalign(ctx->align, ctx->size);
		if (!ctx->buf) {
			fprintf(stderr, "Couldn't allocate work buf.\n");
			err = -ENOMEM;
			return err;
		}
	}

	return err;
}

static void free_mem(struct run_ctx *ctx)
{
	if (ctx->huge) {
		free_hugepage_region(ctx->buf);
		reset_huge_tlb_pages(0);
	} else {
		free(ctx->buf);
	}
}

static int set_rlimit(struct run_ctx *ctx)
{
	struct rlimit rlim, after_rlim;
	int ret;

	ret = getrlimit(RLIMIT_MEMLOCK, &rlim);
	if (ret)
		return ret;

	if (ctx->rlimit) {
		rlim.rlim_cur = ctx->rlimit;
		rlim.rlim_max = ctx->rlimit;
		ret = setrlimit(RLIMIT_MEMLOCK, &rlim);
		if (ret)
			return ret;

		ret = getrlimit(RLIMIT_MEMLOCK, &after_rlim);
		if (after_rlim.rlim_max != ctx->rlimit) {
			fprintf(stderr, "Set rlimit %ld, Got %ld\n",
				ctx->rlimit, after_rlim.rlim_max);
			return -EINVAL;
		}
	}
	return ret;
}

static int lock_mem(struct run_ctx *ctx)
{
	int ret;

	if (ctx->lock_memory)
		ret = mlock(ctx->buf, ctx->size);
	return ret;
}

static int drop_ipc_lock_cap(void)
{
	cap_value_t capList[1];
	cap_t caps;
	int ret;

	/* Retrieve caller's current capabilities */
	caps = cap_get_proc();
	if (caps == NULL)
		return -EINVAL;

	/* Change setting of 'capability' in the effective set of 'caps'. The
	 * third argument, 1, is the number of items in the array 'capList'.
	 */
	capList[0] = CAP_IPC_LOCK;
	ret = cap_set_flag(caps, CAP_EFFECTIVE, 1, capList, CAP_CLEAR);
	if (ret)
		goto err;

	ret = cap_set_proc(caps);
	if (ret)
		goto err;

	ret = cap_set_flag(caps, CAP_PERMITTED, 1, capList, CAP_CLEAR);
	if (ret)
		goto err;

	ret = cap_set_proc(caps);
err:
	cap_free(caps);
	return ret;
}

static int setup_ipc_lock_cap(struct run_ctx *ctx)
{
	int ret = 0;

	if (ctx->drop_ipc_lock_cap)
		ret = drop_ipc_lock_cap();
	return ret;
}

static int setup_test(struct run_ctx *ctx, struct ibv_device *ib_dev)
{
	int err = 0;

	err = set_rlimit(ctx);
	if (err) {
		fprintf(stderr, "Couldn't change rlimit size %ld\n",
			ctx->rlimit);
		goto err;
	}
	err = setup_ipc_lock_cap(ctx);
	if (err) {
		fprintf(stderr, "Couldn't drop ipc lock capability\n");
		goto err;
	}

	err = alloc_mem(ctx);
	if (err) {
		fprintf(stderr, "Couldn't allocate memory of size %ld\n",
			ctx->size);
		goto err;
	}
	err = lock_mem(ctx);
	if (err) {
		fprintf(stderr, "Couldn't lock memory of size %ld\n",
			ctx->size);
		goto err;
	}

	ctx->context = ibv_open_device(ib_dev);
	if (!ctx->context) {
		fprintf(stderr, "Couldn't get context for %s\n",
			ibv_get_device_name(ib_dev));
		goto err;
	}

	ctx->pd = ibv_alloc_pd(ctx->context);
	if (!ctx->pd) {
		fprintf(stderr, "Couldn't allocate PD\n");
		err = -ENOMEM;
		goto err;
	}

	if (ctx->write_pattern) {
		memset(ctx->buf, ctx->pattern, ctx->size);
	}
 	ctx->mr_list = calloc(ctx->count, sizeof(struct ibv_mr*));
	if (!ctx->mr_list) {
		fprintf(stderr, "Couldn't allocate mr list memory\n");
		err = -ENOMEM;
		goto err;
	}
	ctx->access_flags = IBV_ACCESS_LOCAL_WRITE;
	if (ctx->odp)
		ctx->access_flags |= IBV_ACCESS_ON_DEMAND;
	printf("Configuration\n");
	printf("size = ");
	print_size(ctx->size);
	printf("\n");
	printf("align = ");
	print_size(ctx->align);
	printf("\n");
	printf("count = ");
	print_size(ctx->count);
	printf("\n");
	printf("hugetlb = %s\n", ctx->huge ? "enabled" : "disabled");
	printf("odp = %s\n", ctx->odp ? "enabled" : "disabled");
err:
	return err;
}

static void cleanup_test(struct run_ctx *ctx)
{
	if (ctx->pd)
		ibv_dealloc_pd(ctx->pd);
	if (ctx->context)
		ibv_close_device(ctx->context);
	if (ctx)
		free_mem(ctx);
}

int main(int argc, char **argv)
{
	struct statistics reg_time, dereg_time;
	struct ibv_device **dev_list;
	struct ibv_device *ib_dev;
	struct run_ctx *ctx;
	long long time_now;
	int err;
	int i;

	setvbuf(stdout, NULL, _IOLBF, 0);

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		perror("Failed to get IB devices list");
		return 1;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		err = -ENOMEM;
		goto err;
	}
	ctx->size = sysconf(_SC_PAGESIZE);
	ctx->page_size = sysconf(_SC_PAGESIZE);
	ctx->align = sysconf(_SC_PAGESIZE);
	ctx->count = 1;

	parse_options(ctx, argc, argv);

	if (!ctx->ibdev_name) {
		ib_dev = *dev_list;
		if (!ib_dev) {
			fprintf(stderr, "No IB devices found\n");
			err = -ENODEV;
			goto err;
		}
	} else {
		int i;
		for (i = 0; dev_list[i]; i++) {
			if (!strcmp(ibv_get_device_name(dev_list[i]), ctx->ibdev_name))
				break;
		}
		ib_dev = dev_list[i];
		if (!ib_dev) {
			fprintf(stderr, "IB device %s not found\n", ctx->ibdev_name);
			err = -ENODEV;
			goto err;
		}
	}

	err = setup_test(ctx, ib_dev);
	if (err)
		goto err;

	time_now = current_time();
	start_statistics(&reg_time, time_now);

	for (i = 0; i < ctx->count; i++) {
		ctx->mr_list[i] = ibv_reg_mr(ctx->pd, ctx->buf,
				     ctx->size, ctx->access_flags);
		if (!ctx->mr_list[i]) {
			fprintf(stderr, "Couldn't register MR\n");
			err = -ENOMEM;
			goto mr_cleanup;
		}
	}

	time_now = current_time();
	finish_statistics(&reg_time, time_now);

	start_statistics(&dereg_time, time_now);

	for (i = 0; i < ctx->count; i++) {
		ibv_dereg_mr(ctx->mr_list[i]);
	}

	time_now = current_time();
	finish_statistics(&dereg_time, time_now);

	printf("registration time = ");
	print_time(reg_time.load_time);
	printf("\n");
	printf("deregistration time = ");
	print_time(dereg_time.load_time);
	printf("\n");
	cleanup_test(ctx);
	ibv_free_device_list(dev_list);
	return 0;

mr_cleanup:
	for (; i > 0; i--) {
		ibv_dereg_mr(ctx->mr_list[i]);
	}
err:
	cleanup_test(ctx);
	ibv_free_device_list(dev_list);
	return err;
}
