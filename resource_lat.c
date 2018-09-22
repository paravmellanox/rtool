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
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef VERSION
#define VERSION "0.1"
#endif

#define _GNU_SOURCE

#include <sys/param.h>
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
#include <sys/types.h>
#include <unistd.h>

#include "options.h"

static pthread_barrier_t run_barrier;

struct statistics {
	long long start, finish, load_time;
};

struct time_stats {
	struct statistics total;
	long long min, max, avg;
	long long count;
};

struct thread_ctx {
	uint8_t *buf;
	union {
		struct ibv_mr **mr_list;
		struct ibv_pd **pd_list;
		struct ibv_context **uctx_list;
		struct ibv_mw **mw_list;
	} u;
	struct ibv_cq **cq_list;
	struct ibv_qp **qp_list;
	struct time_stats alloc_stats;
	struct time_stats free_stats;
	long long issued;
};

struct run_ctx {
	struct ibv_device *device;
	struct ibv_context *context;
	struct ibv_pd *pd;

	uint64_t size;
	uint64_t mr_size;	/* mr_size and size are same if all MR
				 * register the same pages.
				 * Otherwise size = num_mrs * mr_size.
				 */
	uint64_t min_mr_size; 	/*
				 * this is the min_mr size to test
				 * when testing with different sizes.
				 * starting from PAGE_SIZE to
				 * mr_size.
				 */
	uint64_t max_mr_size;	/* Do MR tests from min_mr_size to
				 * max_mr_size with doubling MR size
				 * on each iteration.
				 */
	uint64_t page_size;
	uint64_t align;
	uint64_t rlimit;
	uint64_t rlimit_set;
	int access_flags;

	int huge;
	int mmap;
	int odp;
	int lock_memory;
	int dedicated_pages;	/* Each MR gets dedicated pages */
	int read_fault;
	int count;		/* resource/operation count */
	int iter;		/* iteration - how many times to operate */
	int threads;
	int write_pattern;
	int drop_ipc_lock_cap;
	int segfault;
	int wait;
	int report_interval;
	char pattern;
	char *ibdev_name;
	char *resource_type;
	uint64_t step_size;	/* every new MR will be at this
				 * step_size from base address.
				 */
};

struct thread_start_info {
	pthread_t thread;
	struct run_ctx *ctx;
	struct thread_ctx t_ctx;
	int created;
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
	printf("  -c --count=<count>       number of resources (i.e. MR, PD etc) to alloc/register\n");
	printf("  -r --rlimit=<bytes>      memory resource hard limit in bytes\n");
	printf("  -i --iter=iteration      how many times to iterarate the operation\n");
	printf("  -u --huge                use huge pages\n");
	printf("  -o --odp                 use ODP registration\n");
	printf("  -t --threads=<threads>   Number of parallel threads\n");
	printf("  -a --assign              use dedicated pages for each MR\n");
	printf("  -A --all                 use all MR sizes starting from PAGE_SIZE to size\n");
	printf("  -m --mmap                use mmap for allocation for huge pages\n");
	printf("  -I --interval            seconds between periodic reports\n");
	printf("  -L --lock                lock memory before registration\n");
	printf("  -f --fault               read page fault memory before registration\n");
	printf("  -D --drop_ipc_lock       drop ipc lock capability before registration\n");
	printf("  -R --resource            resource type (pd, mr, uctx, mw, qp)\n");
	printf("  -S --segfault            seg fault after registration\n");
	printf("  -W --wait                Wait for user signal before resource creation and destroy\n");
	printf("  -h                       display this help message\n");
	printf("  -v                       display program version\n");
}

void version(const char *argv0)
{
	printf("%s %s\n", argv0, VERSION);
}

static void parse_options(struct run_ctx *ctx, int argc, char **argv)
{
	static struct option long_options[] = {
		{ .name = "ibdev",    .has_arg = 1, .val = 'd' },
		{ .name = "size",     .has_arg = 1, .val = 's' },
		{ .name = "align",    .has_arg = 1, .val = 'l' },
		{ .name = "iter",     .has_arg = 1, .val = 'i' },
		{ .name = "pattern",  .has_arg = 1, .val = 'p' },
		{ .name = "threads",  .has_arg = 1, .val = 't' },
		{ .name = "rlimit",   .has_arg = 1, .val = 'r' },
		{ .name = "count",    .has_arg = 1, .val = 'c' },
		{ .name = "interval", .has_arg = 1, .val = 'I' },
		{ .name = "resource", .has_arg = 1, .val = 'R' },
		{ .name = "huge",     .has_arg = 0, .val = 'u' },
		{ .name = "odp",      .has_arg = 0, .val = 'o' },
		{ .name = "assign",   .has_arg = 0, .val = 'a' },
		{ .name = "all",      .has_arg = 0, .val = 'A' },
		{ .name = "lock",     .has_arg = 0, .val = 'L' },
		{ .name = "fault",    .has_arg = 0, .val = 'f' },
		{ .name = "drop_ipc", .has_arg = 0, .val = 'D' },
		{ .name = "segfault", .has_arg = 0, .val = 'S' },
		{ .name = "wait",     .has_arg = 0, .val = 'W' },
		{ .name = "mmap",     .has_arg = 0, .val = 'm' },
		{ .name = NULL }
	};
	int opt;

	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}

	while ((opt = getopt_long(argc, argv, "hv:d:I:R:p:r:s:t:i:c:l:uoLfDSWmaA",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'v':
			version(argv[0]);
			exit(0);
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'a':
			ctx->dedicated_pages = 1;
			break;
		case 'd':
			ctx->ibdev_name = malloc(strlen(optarg));
			if (!ctx->ibdev_name) {
				fprintf(stderr, "Couldn't allocate mem.\n");
				exit(1);
			}
			strcpy(ctx->ibdev_name, optarg);
			break;
		case 'R':
			ctx->resource_type = malloc(strlen(optarg));
			if (!ctx->resource_type) {
				fprintf(stderr, "Couldn't allocate mem.\n");
				exit(1);
			}
			strcpy(ctx->resource_type, optarg);
			break;
		case 's':
			ctx->size = parse_size(optarg);
			break;
		case 'A':
			ctx->min_mr_size = sysconf(_SC_PAGESIZE);
			break;
		case 'I':
			ctx->report_interval = parse_int(optarg);
			break;
		case 'l':
			ctx->align = parse_size(optarg);
			break;
		case 'm':
			ctx->mmap = 1;
			break;
		case 'c':
			ctx->count = parse_int(optarg);
			break;
		case 'i':
			ctx->iter = parse_int(optarg);
			break;
		case 'r':
			ctx->rlimit = parse_size(optarg);
			ctx->rlimit_set = 1;
			break;
		case 'p':
			ctx->write_pattern = 1;
			ctx->pattern = *((char*)optarg);
			break;
		case 't':
			ctx->threads = parse_int(optarg);
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
		case 'f':
			ctx->read_fault = 1;
			break;
		case 'D':
			ctx->drop_ipc_lock_cap = 1;
			break;
		case 'S':
			ctx->segfault = 1;
			break;
		case 'W':
			ctx->wait = 1;
			break;
		}
	}
}

static void normalize_sizes(struct run_ctx *ctx)
{
	if ((strcmp(ctx->resource_type, "mr") == 0) ||
	    (strcmp(ctx->resource_type, "mw") == 0)) {
		ctx->mr_size = ctx->size;
		if (ctx->dedicated_pages) {
			ctx->step_size = ctx->size;
			ctx->size = ctx->size * ctx->count;
		} else {
			ctx->step_size = 0;
		}
	}
}

static void start_statistics(struct statistics *s)
{
	s->start = current_time();
}

static void finish_statistics(struct statistics *s)
{
	s->finish = current_time();
	s->load_time += s->finish - s->start;
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

static int config_hugetlb_kernel(const struct run_ctx *ctx)
{
	long hpage_size = gethugepagesize();
	uint64_t num_hpages;

	if (hpage_size == 0)
		return -EINVAL;

	num_hpages = (ctx->size * ctx->threads) / hpage_size;
	if (num_hpages == 0)
		num_hpages = 1;

	return config_hugetlb_pages(num_hpages);
}

static int alloc_hugepage_mem(const struct run_ctx *ctx, struct thread_ctx *t_ctx)
{
	int mmap_flags = MAP_ANONYMOUS | MAP_PRIVATE;

	if (ctx->mmap) {
		mmap_flags |= MAP_HUGETLB;
		t_ctx->buf = mmap(0, ctx->size, PROT_WRITE | PROT_READ,
				mmap_flags, 0, 0);
		if (t_ctx->buf == MAP_FAILED) {
			perror("mmap");
			return -ENOMEM;
		}
	} else {
		t_ctx->buf = get_hugepage_region(ctx->size, GHR_STRICT | GHR_COLOR);
		if (!t_ctx->buf) {
			perror("mmap");
			return -ENOMEM;
		}
	}
	return 0;
}

static int alloc_mem(const struct run_ctx *ctx, struct thread_ctx *t_ctx)
{
	int err = 0;

	if (ctx->huge) {
		err = config_hugetlb_kernel(ctx);
		if (err) {
			printf("fail to configure hugetlb\n");
			err = -EINVAL;
			return err;
		}
		err = alloc_hugepage_mem(ctx, t_ctx);
		if (err)
			return err;
	} else {
		t_ctx->buf = memalign(ctx->align, ctx->size);
		if (!t_ctx->buf) {
			fprintf(stderr, "Couldn't allocate work buf.\n");
			err = -ENOMEM;
			return err;
		}
	}

	return err;
}

static void free_mem(const struct run_ctx *ctx, struct thread_ctx *t_ctx)
{
	if (ctx->huge) {
		if (t_ctx->buf)
			free_hugepage_region(t_ctx->buf);
		reset_huge_tlb_pages(0);
	} else {
		if (t_ctx->buf)
			free(t_ctx->buf);
	}
}

static int set_rlimit(struct run_ctx *ctx)
{
	struct rlimit rlim, after_rlim;
	int ret;

	ret = getrlimit(RLIMIT_MEMLOCK, &rlim);
	if (ret)
		return ret;

	if (ctx->rlimit_set) {
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

static int lock_mem(const struct run_ctx *ctx, struct thread_ctx *t_ctx)
{
	int ret;

	if (ctx->lock_memory)
		ret = mlock(t_ctx->buf, ctx->size);
	return ret;
}

static void read_fault(const struct run_ctx *ctx, struct thread_ctx *t_ctx)
{
	uint8_t dummy_buf[4096];
	uint8_t *read_ptr = t_ctx->buf;
	uint64_t read_size = ctx->size;

	if (!ctx->read_fault)
		return;

	while (read_size) {
		memcpy(&dummy_buf[0], read_ptr,
		       MIN(sizeof(dummy_buf), read_size));
		read_ptr += MIN(sizeof(dummy_buf), read_size);
		read_size -= MIN(sizeof(dummy_buf), read_size);
	}
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

enum resource_id {
	RTYPE_PD,
	RTYPE_MR,
	RTYPE_UCTX,
	RTYPE_MW,
	RTYPE_QP,
	RTYPE_MAX
};

struct resource_info {
	enum resource_id id;
	const char *name;
};

static const struct resource_info resource_types[] = {
	{ RTYPE_PD, "pd", },
	{ RTYPE_MR, "mr", },
	{ RTYPE_UCTX, "uctx", },
	{ RTYPE_MW, "mw", },
	{ RTYPE_QP, "qp", },
	{ -1, NULL, },
};

static int check_resource_type(char *type)
{
	int err = -EINVAL;
	int i = 0;

	while (resource_types[i].name) {
		if (strcmp(type, resource_types[i].name)) {
			i++;
			continue;
		}
		err = resource_types[i].id;
		break;
	}
	return err;
}


static int alloc_resource_holder(const struct run_ctx *ctx,
				 struct thread_ctx *t)
{
	int type;

	type = check_resource_type(ctx->resource_type);
	if (type == RTYPE_QP) {
		t->qp_list = calloc(ctx->count, sizeof(struct ibv_qp*));
		if (!t->qp_list) {
			fprintf(stderr, "Couldn't allocate qp list memory\n");
			return -ENOMEM;
		}
		return 0;
	}

	t->u.mr_list = calloc(ctx->count, sizeof(struct ibv_mr*));
	if (!t->u.mr_list) {
		fprintf(stderr, "Couldn't allocate list memory\n");
		return -ENOMEM;
	}
	return 0;
}
static void update_min(const struct statistics *stat, struct time_stats *t)
{
	if (stat->load_time < t->min)
		t->min = stat->load_time;
}

static void update_max(const struct statistics *stat, struct time_stats *t)
{
	if (stat->load_time > t->max)
		t->max = stat->load_time;
}

static void update_avg(const struct statistics *stat,
			   struct time_stats *t)
{
	long long avg = t->avg;
	long long old_sum = avg * t->count;
	long long new_avg = (old_sum + stat->load_time) / (t->count + 1);

	t->avg = new_avg;
}

static int alloc_uctx(const struct run_ctx *ctx, struct thread_ctx *t, int i)
{
	int err = 0;

	t->u.uctx_list[i] = ibv_open_device(ctx->device);
	if (!t->u.uctx_list[i]) {
		fprintf(stderr, "alloc pd count = %d\n", i);
		err = -ENOMEM;
	}
	return err;
}

static int alloc_pd(const struct run_ctx *ctx, struct thread_ctx *t, int i)
{
	int err = 0;

	t->u.pd_list[i] = ibv_alloc_pd(ctx->context);
	if (!t->u.pd_list[i]) {
		fprintf(stderr, "alloc pd count = %d\n", i);
		err = -ENOMEM;
	}
	return err;
}

static int alloc_mr(const struct run_ctx *ctx, struct thread_ctx *t, int i)
{
	int err = 0;

	t->u.mr_list[i] =
			ibv_reg_mr(ctx->pd, t->buf + (i * ctx->step_size),
				   ctx->mr_size, ctx->access_flags);
	if (!t->u.mr_list[i]) {
		fprintf(stderr, "Registered MR count = %d\n", i);
		err = -ENOMEM;
	}
	return err;
}

static int alloc_mw(const struct run_ctx *ctx, struct thread_ctx *t, int i)
{
	int err = 0;

	t->u.mw_list[i] = ibv_alloc_mw(ctx->pd, IBV_MW_TYPE_2);
	if (!t->u.mw_list[i]) {
		fprintf(stderr, "Registered MW count = %d\n", i);
		err = -ENOMEM;
	}
	return err;
}

static int alloc_qp(const struct run_ctx *ctx, struct thread_ctx *t, int i)
{
	struct ibv_qp_init_attr qp_attr = { 0 };
	int err = 0;

	qp_attr.send_cq = qp_attr.recv_cq = NULL;
	qp_attr.cap.max_send_wr = 128;
	qp_attr.cap.max_recv_wr = 128;
	qp_attr.cap.max_send_sge = 2;
	qp_attr.cap.max_recv_sge = 2;
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.sq_sig_all = 1;

	t->qp_list[i] = ibv_create_qp(ctx->pd, &qp_attr);
	if (!t->qp_list[i]) {
		fprintf(stderr, "Registered QP count = %d\n", i);
		err = -ENOMEM;
	}
	return err;
}

static int allocate_resources(const struct run_ctx *ctx, struct thread_ctx *t)
{
	struct statistics stat = { 0 };
	int err = 0;
	int type;
	int i;

	type = check_resource_type(ctx->resource_type);
	if (type < 0)
		return err;

	for (i = 0; i < ctx->count; i++) {
		start_statistics(&stat);
		switch (type) {
		case RTYPE_UCTX:
			err = alloc_uctx(ctx, t, i);
			break;
		case RTYPE_PD:
			err = alloc_pd(ctx, t, i);
			break;
		case RTYPE_MR:
			err = alloc_mr(ctx, t, i);
			break;
		case RTYPE_MW:
			err = alloc_mw(ctx, t, i);
			break;
		case RTYPE_QP:
			err = alloc_qp(ctx, t, i);
			break;
		}
		finish_statistics(&stat);
		if (err)
			break;
		update_min(&stat, &t->alloc_stats);
		update_max(&stat, &t->alloc_stats);
		update_avg(&stat, &t->alloc_stats);
		t->alloc_stats.count++;
	}
	return err;
}

static void free_uctx(struct thread_ctx *t, int i)
{
	if (t->u.uctx_list[i])
		ibv_close_device(t->u.uctx_list[i]);
}

static void free_pd(struct thread_ctx *t, int i)
{
	if (t->u.pd_list[i])
		ibv_dealloc_pd(t->u.pd_list[i]);
}

static void free_mr(struct thread_ctx *t, int i)
{
	if (t->u.mr_list[i])
		ibv_dereg_mr(t->u.mr_list[i]);
}

static void free_mw(struct thread_ctx *t, int i)
{
	if (t->u.mw_list[i])
		ibv_dealloc_mw(t->u.mw_list[i]);
}

static void free_qp(struct thread_ctx *t, int i)
{
	if (t->qp_list[i])
		ibv_destroy_qp(t->qp_list[i]);
}

static void free_resources(const struct run_ctx *ctx, struct thread_ctx *t)
{
	struct statistics stat = { 0 };
	int err;
	int i;

	err = check_resource_type(ctx->resource_type);
	if (err < 0)
		return;

	for (i = 0; i < ctx->count; i++) {
		start_statistics(&stat);
		switch (err) {
		case RTYPE_UCTX:
			free_uctx(t, i);
		case RTYPE_PD:
			free_pd(t, i);
			break;
		case RTYPE_MR:
			free_mr(t, i);
			break;
		case RTYPE_MW:
			free_mw(t, i);
			break;
		case RTYPE_QP:
			free_qp(t, i);
			break;
		}
		finish_statistics(&stat);
		update_min(&stat, &t->free_stats);
		update_max(&stat, &t->free_stats);
		update_avg(&stat, &t->free_stats);
		t->free_stats.count++;
	}
}

static int do_thread_init(const struct run_ctx *ctx, struct thread_ctx *t_ctx)
{
	int err;

	err = alloc_resource_holder(ctx, t_ctx);
	if (err) {
		fprintf(stderr, "Couldn't allocate resource holding memory\n");
		goto err;
	}
	t_ctx->alloc_stats.min = LLONG_MAX;
	t_ctx->alloc_stats.max = LLONG_MIN;
	t_ctx->alloc_stats.count = 0;
	t_ctx->free_stats.min = LLONG_MAX;
	t_ctx->free_stats.max = LLONG_MIN;
	t_ctx->free_stats.count = 0;

	err = alloc_mem(ctx, t_ctx);
	if (err) {
		fprintf(stderr, "Couldn't allocate memory of size %ld\n",
			ctx->size);
		goto err;
	}
	err = lock_mem(ctx, t_ctx);
	if (err) {
		fprintf(stderr, "Couldn't lock memory of size %ld\n",
			ctx->size);
		goto err;
	}

	read_fault(ctx, t_ctx);

	if (ctx->write_pattern)
		memset(t_ctx->buf, ctx->pattern, ctx->size);
err:
	return err;
}

static void do_thread_cleanup(const struct run_ctx *ctx, struct thread_ctx *t_ctx)
{
	free_mem(ctx, t_ctx);
}

static int setup_test(struct run_ctx *ctx, struct ibv_device *ib_dev)
{
	int err;

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

	ctx->access_flags = IBV_ACCESS_LOCAL_WRITE;
	if (ctx->odp)
		ctx->access_flags |= IBV_ACCESS_ON_DEMAND;

	ctx->device = ib_dev;
err:
	return err;
}

static void print_lat_stats(uint64_t size, struct time_stats *s, char *str)
{
	if (size) {
		printf("size: "); print_size(size); printf(" ");
	}

	printf("%s lat: ", str);
	printf(" min="); print_time(s->min); printf(",");
	printf(" max="); print_time(s->max); printf(",");
	printf(" avg="); print_time(s->avg); printf(",");
	printf(" tot="); print_time(s->total.load_time);
	printf("\n");
}

static void cleanup_test(struct run_ctx *ctx)
{
	if (ctx->pd)
		ibv_dealloc_pd(ctx->pd);
	if (ctx->context)
		ibv_close_device(ctx->context);
}

static void check_for_segfault(const struct run_ctx *ctx)
{
	if (ctx->segfault)
		*((char*)NULL) = 'a';
}

static void check_for_user_signal(const struct run_ctx *ctx)
{
	char temp;

	if (ctx->wait) {
		printf("Waiting for user input to proceed.\n");
		scanf("%c", &temp);
	}
}

static void dump_global_test_cfg(struct run_ctx *ctx)
{
	printf("Configuration\n");
	printf("pid     = %d\n", getpid());
	printf("align   = "); print_size(ctx->align); printf("\n");
	printf("count   = "); print_int(ctx->count); printf("\n");
	printf("hugetlb = %s\n", ctx->huge ? "enabled" : "disabled");
	printf("odp     = %s\n", ctx->odp ? "enabled" : "disabled");
	printf("mmap    = %s\n", ctx->mmap ? "enabled" : "disabled");
}

static int do_one_test(const struct run_ctx *ctx, struct thread_ctx *t)
{
	int err;

	check_for_user_signal(ctx);

	start_statistics(&t->alloc_stats.total);
	err = allocate_resources(ctx, t);
	finish_statistics(&t->alloc_stats.total);
	if (err) {
		fprintf(stderr, "Couldn't register resources\n");
		goto cleanup;
	}

	check_for_user_signal(ctx);
	check_for_segfault(ctx);

	start_statistics(&t->free_stats.total);
	free_resources(ctx, t);
	finish_statistics(&t->free_stats.total);
	return 0;

cleanup:
	free_resources(ctx, t);
	return err;
}

static void* do_run(void *arg)
{
	struct thread_start_info *info = arg;
	struct thread_ctx *t_ctx = &info->t_ctx;
	const struct run_ctx *ctx = info->ctx;
	int i = 0;
	int err;

	err = do_thread_init(ctx, t_ctx);
	if (err)
		goto done;

	/* Wait for all threads to finish their allocation */
	pthread_barrier_wait(&run_barrier);
	do {
		err = do_one_test(ctx, t_ctx);
		if (err)
			break;

		t_ctx->issued++;
		i++;
	} while (i < ctx->iter);

	do_thread_cleanup(ctx, t_ctx);
done:
	if (ctx->threads > 1)
		pthread_exit(NULL);
	return NULL;
}

struct print_thread_ctx {
	struct thread_start_info *threads;
	const struct run_ctx *ctx;
	pthread_t thread;
};

static void print_results(const struct run_ctx *ctx, struct thread_start_info *threads)
{
	int i;

	for (i = 0; i < ctx->threads; i++) {
		if (!threads[i].t_ctx.issued)
			continue;

		print_lat_stats(ctx->mr_size, &threads[i].t_ctx.alloc_stats, "alloc");
		print_lat_stats(ctx->mr_size, &threads[i].t_ctx.free_stats,  "free ");
		printf("issued:  "); print_int(threads[i].t_ctx.issued); printf("\n");
	}
}

static void* results_printer(void *arg)
{
	struct print_thread_ctx *print_ctx = arg;
	const struct run_ctx *ctx = print_ctx->ctx;
	struct thread_start_info *threads = print_ctx->threads;

	/* this barrier also ensures that all worker threads are created */
	pthread_barrier_wait(&run_barrier);

	while(1) {
		print_results(ctx, threads);
		sleep(ctx->report_interval);
	}
	pthread_exit(NULL);
	return NULL;
}

static int run_threads(struct run_ctx *ctx, struct thread_start_info *threads)
{
	int err;
	int i;

	for (i = 0; i < ctx->threads; i++) {
		threads[i].ctx = ctx;

		err = pthread_create(&threads[i].thread, NULL,
				     &do_run, &threads[i]);
		if (err)
			break;
		threads[i].created = 1;
	}

	for (i = 0; i < ctx->threads; i++) {
		if (!threads[i].created)
			continue;

		pthread_join(threads[i].thread, NULL);

	}
	return err;
}

static int run_one_instance(struct run_ctx *ctx,
			    struct thread_start_info *threads)
{
	threads[0].ctx = ctx;
	do_run(&threads[0]);
	return 0;
}

static int do_test(struct run_ctx *ctx, struct ibv_device *ib_dev)
{
	struct print_thread_ctx print_ctx = { 0 };
	struct thread_start_info *threads;
	int waiters = ctx->threads;
	int err;

	err = setup_test(ctx, ib_dev);
	if (err)
		goto err;

	threads = calloc(ctx->threads, sizeof(*threads));
	if (!threads) {
		err = -ENOMEM;
		goto err;
	}

	waiters += (ctx->report_interval ? 1 : 0);
	pthread_barrier_init(&run_barrier, NULL, waiters);
	print_ctx.ctx = ctx;
	print_ctx.threads = threads;

	if (ctx->report_interval) {
		err = pthread_create(&print_ctx.thread,
				     NULL, &results_printer, &print_ctx);
		if (err)
			goto thr_err;
	}

	if (ctx->threads > 1)
		err = run_threads(ctx, threads);
	else
		err = run_one_instance(ctx, threads);

	if (ctx->report_interval) {
		pthread_cancel(print_ctx.thread);
		pthread_join(print_ctx.thread, NULL);
	}

	print_results(ctx, threads);
thr_err:
	free(threads);
err:
	pthread_barrier_destroy(&run_barrier);
	cleanup_test(ctx);
	return err;
}

int main(int argc, char **argv)
{
	struct ibv_device **dev_list;
	struct ibv_device *ib_dev;
	struct run_ctx *ctx;
	int err;

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
	ctx->iter = 1;
	ctx->threads = 1;

	parse_options(ctx, argc, argv);

	ctx->max_mr_size = ctx->size;
	if (ctx->min_mr_size == 0)
		ctx->min_mr_size = ctx->max_mr_size;

	if (!ctx->resource_type)
		ctx->resource_type = "mr";
	else {
		err = check_resource_type(ctx->resource_type);
		if (err < 0) {
			fprintf(stderr, "Invalid resource type = %s\n",
				ctx->resource_type);
			goto done;
		}
	}

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

	dump_global_test_cfg(ctx);

	while (ctx->min_mr_size <= ctx->max_mr_size) {
		ctx->size = ctx->min_mr_size;
		normalize_sizes(ctx);
		err = do_test(ctx, ib_dev);

		if (ctx->min_mr_size == ctx->max_mr_size)
			break;

		ctx->min_mr_size *= 2;
		/* when mr size is not aligned, still need to calculate for
		 * maximum size.
		 */
		if (ctx->min_mr_size > ctx->max_mr_size)
			ctx->min_mr_size = ctx->max_mr_size;
	}
err:
	ibv_free_device_list(dev_list);
done:
	return err;
}
