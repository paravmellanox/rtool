/*
 *  rdmaio -- rdma io generation tool
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
#define VERSION "0.1 alpha"
#endif

#define _GNU_SOURCE
#include <endian.h>
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
#include <semaphore.h>
#include <hugetlbfs.h>
#include <sys/time.h>
#include <malloc.h>
#include <inttypes.h>
#include <infiniband/verbs.h>
#include <infiniband/sa.h>
#include <rdma/rdma_cma.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "options.h"

#define RDMAIO_Q_DEPTH 1024

struct rdmaio_cmd {
	uint8_t cmd[64];
};

struct rdmaio_rx_wr {
	struct rdmaio_cmd *cmd;
	struct ibv_recv_wr wr;
	struct ibv_sge sge;
};

struct rdmaio_tx_wr {
	struct rdmaio_cmd *cmd;
	struct ibv_send_wr rdma_wr;
	struct ibv_send_wr send_wr;
	struct ibv_sge sge;
};

enum rdmaio_cm_state {
	RDMAIO_CM_STATE_ADDR_RESOLVED,
	RDMAIO_CM_STATE_ROUTE_RESOLVED,
	RDMAIO_CM_CONNECTED,
	RDMAIO_CM_DISCONNECTED,
	RDMAIO_CM_FATAL_ERROR,
};

struct rdma_connection {
	struct ibv_comp_channel *cq_channel;
	struct ibv_cq *cq;
	struct ibv_pd *pd;

	struct {
		struct rdmaio_cmd *cmds;
		struct rdmaio_rx_wr *wrs;
		struct ibv_mr *cmds_mr;
		int recv_cnt;
	} rx;
	struct {
		struct rdmaio_cmd *cmds;
		struct rdmaio_tx_wr *wrs;
		struct ibv_mr *cmds_mr;
	} tx;
	pthread_t cq_thread;
	int id;

	enum rdmaio_cm_state  state;
	struct rdma_cm_id *cm_id;	/* client id or server child id */
	struct rdmacm_client_ctx *c_ctx;
};

struct rdmacm_client_ctx {
	pthread_t cm_thread;
	sem_t sem;
};

struct rdmacm_run_ctx {
	struct rdma_event_channel *channel;
	struct rdma_cm_event *event;
	struct rdma_cm_id *listen_cm_id;

	int next_free_client_index;
	struct rdma_connection clients[128];

	struct rdmacm_client_ctx c_ctx;
};

struct run_ctx {
	struct ibv_context *context;
	char *ibdev_name;
	uint64_t size;
	uint64_t page_size;
	uint64_t align;
	uint64_t count;
	uint64_t offset;
	void *buf;
	int access_flags;

	int huge;
	int odp;
	int write_pattern;
	char pattern;
	int server;
	char *host;
	uint16_t port;	/* network byte order */
	int connections;
	int skip_route_resolve;

	struct rdmacm_run_ctx r_ctx;
 	struct sockaddr_storage sockaddr;
	struct sockaddr_storage src_sockaddr;
};

#define HUGE_PAGE_KPATH "/proc/sys/vm/nr_hugepages"

static int parse_address(struct run_ctx *ctx, const char *input_addr)
{
	struct addrinfo *info;
	int ret;

	ret = getaddrinfo(input_addr, NULL, NULL, &info);
	if (ret) {
		printf("err (%s) - invalid hostname or IP address\n",
		       gai_strerror(ret));
		return ret;
	}

	if (info->ai_family == PF_INET)
		memcpy(&ctx->sockaddr, info->ai_addr, sizeof(struct sockaddr_in));
	else if (info->ai_family == PF_INET6)
		memcpy(&ctx->sockaddr, info->ai_addr, sizeof(struct sockaddr_in6));
	else
		ret = -1;
	
	freeaddrinfo(info);
	return ret;
}

static void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("%s\n", argv0);
	printf("Options:\n");
	printf("  -a --address=<ip_address>	ip address to bind or connect to\n");
	printf("  -S --size=<size>		size of mr in bytes (default 4096)\n");
	printf("  -l --align=<align_size>	align memory allocation to this size\n");
	printf("  -n --count=<count>		number of wr operations\n");
	printf("  -u --huge			use huge pages\n");
	printf("  -j --skip			Skip route lookup for subsequent connections\n");
	printf("  -s --server			run in server mode\n");
	printf("  -c --client			run in client mode, connecting to <host>\n");
	printf("  -C --connections		number of connections\n");
	printf("  -o --odp			use ODP registration\n");
	printf("  -p --port			server port to listen on/connect to\n");
	printf("  -f --offset			use offset in registered MR for data transfer\n");
	printf("  -h				display this help message\n");
	printf("  -v				display program version\n");
}

void version(const char *argv0)
{
	printf("%s %s\n", argv0, VERSION);
}

void parse_options(struct run_ctx *ctx, int argc, char **argv)
{
	int opt;
	int ret = 0;

	static struct option long_options[] = {
		{ .name = "address",  .has_arg = 1, .val = 'a' },
		{ .name = "size",     .has_arg = 1, .val = 'S' },
		{ .name = "align",    .has_arg = 1, .val = 'l' },
		{ .name = "pattern",  .has_arg = 1, .val = 'P' },
		{ .name = "count",    .has_arg = 1, .val = 'n' },
		{ .name = "server",   .has_arg = 0, .val = 's' },
		{ .name = "client",   .has_arg = 1, .val = '0' },
		{ .name = "connections",   .has_arg = 1, .val = 'C' },
		{ .name = "huge",     .has_arg = 0, .val = 'u' },
		{ .name = "port",     .has_arg = 1, .val = 'p' },
		{ .name = "skip",     .has_arg = 0, .val = 'j' },
		{ .name = "odp",      .has_arg = 0, .val = 'o' },
		{ .name = "offset",   .has_arg = 1, .val = 'f' },
		{ .name = NULL }
	};

	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}

	while ((opt = getopt_long(argc, argv, "hv:d:P:S:a:C:p:n:f:l:juosc", long_options, NULL)) != -1) {
		switch (opt) {
		case 'v':
			version(argv[0]);
			exit(0);
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'a':
			ret = parse_address(ctx, optarg);
			if (ret)
				goto err;
			break;
		case 'S':
			ctx->size = parse_size(optarg);
			break;
		case 'l':
			ctx->align = parse_size(optarg);
			break;
		case 'n':
			ctx->count = parse_size(optarg);
			break;
		case 'f':
			ctx->offset = parse_size(optarg);
			break;
		case 'C':
			ctx->connections = parse_size(optarg);
			break;
		case 'P':
			ctx->write_pattern = 1;
			ctx->pattern = *((char*)optarg);
			break;
		case 'p':
			ctx->port = atoi(optarg);
			break;
		case 'u':
			ctx->huge = 1;
			break;
		case 'o':
			ctx->odp = 1;
			break;
		case 'j':
			ctx->skip_route_resolve = 1;
			break;
		case 's':
			ctx->server = 1;
			break;
		case 'c':
			ctx->host = (char*)optarg;
			break;
		}
	}
	return;

err:
	exit(1);
}

struct statistics {
	long long start, finish, load_time;
	long long min, max;
};

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

static struct rdma_cm_event *wait_for_event(struct run_ctx *ctx)
{
	int ret;

	ret = rdma_get_cm_event(ctx->r_ctx.channel, &ctx->r_ctx.event);
	if (ret) {
		printf("%s null event.\n", __func__);
		return NULL;
	}

	printf("rdmacm event: %s status = %d id = %p\n",
		rdma_event_str(ctx->r_ctx.event->event),
		ctx->r_ctx.event->status, ctx->r_ctx.event->id);

	if (ctx->r_ctx.event->event == RDMA_CM_EVENT_CONNECT_REQUEST ||
	    ctx->r_ctx.event->event == RDMA_CM_EVENT_ESTABLISHED) {
		printf("listen_id = %p, id = %p\n",
			ctx->r_ctx.event->listen_id, ctx->r_ctx.event->id);
	}
	return ctx->r_ctx.event;
}

static int
rdma_ack_event(struct run_ctx *ctx)
{
	int ret;

	ret = rdma_ack_cm_event(ctx->r_ctx.event);
	return ret;
}

static int create_q(struct rdma_connection *q)
{
	struct ibv_qp_init_attr qp_attr;
	int ret;

	memset(&qp_attr, 0, sizeof(qp_attr));

	q->pd = ibv_alloc_pd(q->cm_id->verbs);
	if (!q->pd) {
		printf("%s fail to create pd\n", __func__);
		return -ENOMEM;
	}

	q->cq_channel = ibv_create_comp_channel(q->cm_id->verbs);
	if (!q->cq_channel) {
		printf("%s fail to create cq channel\n", __func__);
		return -ENOMEM;
	}

	q->cq = ibv_create_cq(q->cm_id->verbs,
			      1023 * 2, q,
			      q->cq_channel,
			      0);
	if (!q->cq) {
		printf("%s fail to create cq\n", __func__);
		return -ENOMEM;
	}
	ret = ibv_req_notify_cq(q->cq, 0);
	if (ret)
		return ret;

	qp_attr.qp_context = q;
	qp_attr.send_cq = q->cq;
	qp_attr.recv_cq = q->cq;
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.sq_sig_all = 1;
	qp_attr.cap.max_send_wr = 1023;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_wr = 1023;
	qp_attr.cap.max_recv_sge = 1;

	ret = rdma_create_qp(q->cm_id, q->pd, &qp_attr);
	if (ret) {
		printf("%s fail to create qp ret = %d\n", __func__, ret);
		goto err;
	}
	return ret;

err:
	ibv_destroy_cq(q->cq);
	ibv_destroy_comp_channel(q->cq_channel);
	ibv_dealloc_pd(q->pd);
	return ret;
}

static void init_rx_cmd_wrs(struct rdma_connection *q,
			    int rx_cmd_size, int rx_cmd_count)
{
	int i;

	for (i = 0; i < rx_cmd_count; i++) {
		q->rx.wrs[i].cmd = &q->rx.cmds[i];
		q->rx.wrs[i].sge.addr = (uintptr_t)&q->rx.cmds[i];
		q->rx.wrs[i].sge.length = rx_cmd_size;
		q->rx.wrs[i].sge.lkey = q->rx.cmds_mr->lkey;

		q->rx.wrs[i].wr.wr_id = (uintptr_t)q->rx.wrs[i].cmd;
		q->rx.wrs[i].wr.sg_list = &q->rx.wrs[i].sge;
		q->rx.wrs[i].wr.num_sge = 1;
	}
}

static int rdmaio_post_recv_wr(struct rdma_connection *q, int index)
{
	struct ibv_recv_wr *bad_wr;
	int ret;

	ret = ibv_post_recv(q->cm_id->qp, &q->rx.wrs[index].wr,
			    &bad_wr);
	return ret;
}

static int setup_rx_cmds_buffers(struct rdma_connection *q,
				 int cmd_size, int cmd_count)
{
	int ret;
	int i;

	q->rx.cmds = calloc(cmd_count, cmd_size);
	if (!q->rx.cmds)
		return -ENOMEM;

	memset(q->rx.cmds, 0, cmd_size * cmd_count);

	q->rx.cmds_mr = ibv_reg_mr(q->pd, q->rx.cmds,
				       cmd_size * cmd_count,
				       IBV_ACCESS_LOCAL_WRITE);
	if (!q->rx.cmds_mr)
		return -ENOMEM;


	q->rx.wrs = calloc(cmd_count, sizeof(*q->rx.wrs));
	if (!q->rx.wrs)
		return -ENOMEM;

	init_rx_cmd_wrs(q, cmd_size, cmd_count);

	for (i = 0; i < cmd_count; i++) {
		ret = rdmaio_post_recv_wr(q, i);
		if (ret)
			break;
	}
	printf("%s i= %d ret = %d\n", __func__, i, ret);
	return ret;
}

static int server_cq_handler(struct rdma_connection *q)
{
	struct ibv_wc wc;
	int ret;

	while (1) {
		ret = ibv_poll_cq(q->cq, 1, &wc);
		if (ret <= 0)
			break;

		if (wc.status) {
			fprintf(stderr, "cqe status = %d\n", wc.status);
			ret = -1;
			goto err;
		}

		switch (wc.opcode) {
		case IBV_WC_SEND:
			break;
		case IBV_WC_RDMA_WRITE:
			break;
		case IBV_WC_RDMA_READ:
			break;
		case IBV_WC_RECV:
			q->rx.recv_cnt++;
			break;
		default:
			printf("unknown completion status=%d opcode=%d\n",
				wc.status, wc.opcode);
			ret = -1;
			goto err;
		}
	}
	if (ret) {
		fprintf(stderr, "cq poll error=%d\n", ret);
		goto err;
	}
	return 0;

err:
	return ret;
}

static void *server_cq_thread(void *arg)
{
	struct rdma_connection *q = arg;
	struct ibv_cq *event_cq;
	void *event_ctx;
	int ret;

	while (1) {
		pthread_testcancel();

		ret = ibv_get_cq_event(q->cq_channel, &event_cq, &event_ctx);
		if (ret) {
			fprintf(stderr, "Failed to get cq event!\n");
			pthread_exit(NULL);
		}
		if (event_cq != q->cq) {
			fprintf(stderr, "Invalid cq =%p\n", event_cq);
			pthread_exit(NULL);
		}
		ret = ibv_req_notify_cq(q->cq, 0);
		if (ret) {
			fprintf(stderr, "fail to arm cq=%p\n", event_cq);
			pthread_exit(NULL);
		}
		ret = server_cq_handler(q);
		ibv_ack_cq_events(q->cq, 1);
		if (ret)
			pthread_exit(NULL);
	}
	return NULL;
}

static int server_start_io_thread(struct rdma_connection *q)
{
	int ret;

	ret = pthread_create(&q->cq_thread, NULL,
			     server_cq_thread, q);
	return ret;
}

static struct rdma_connection* alloc_q(struct run_ctx *ctx)
{
	struct rdma_connection *q;
	int free_idx;

	free_idx = ctx->r_ctx.next_free_client_index;

	q = &ctx->r_ctx.clients[free_idx];
	q->id = free_idx;
	ctx->r_ctx.next_free_client_index++;
	return q;
}

static int server_handle_connect(struct run_ctx *ctx,
				 struct rdma_cm_id *child_id)
{
	struct rdma_conn_param param = { 0 };
	struct rdma_connection *q;
	char resp[20] = { 0 };
	int ret;

	printf("%s allocating q memory\n", __func__);
	q = alloc_q(ctx);
	if (!q)
		return -EINVAL;

	memset(q, 0, sizeof(*q));

	printf("%s creating q id = %p\n", __func__, child_id);
	q->cm_id = child_id;
	q->cm_id->context = q;
	ret = create_q(q);
	if (ret)
		return ret;

	printf("%s done creating qp = %p\n", __func__, child_id);
	param.rnr_retry_count = 7;
	param.flow_control = 1;
	param.initiator_depth = 1;
	param.private_data = &resp[0];
	param.private_data_len = sizeof(resp);

	ret = rdma_accept(q->cm_id, &param);
	if (ret)
		goto err;

	printf("%s done accepting qp = %p\n", __func__, child_id);
	ret = setup_rx_cmds_buffers(q, sizeof(struct rdmaio_cmd),
				    RDMAIO_Q_DEPTH);
	if (ret)
		goto err;

	printf("%s done setup rx buffers = %p\n", __func__, child_id);
	ret = server_start_io_thread(q);
	if (ret)
		goto io_err;

	printf("%s io thread started = %p\n", __func__, child_id);
	return 0;

io_err:
	rdma_disconnect(q->cm_id);
err:
	rdma_destroy_qp(q->cm_id);
	return ret;
}

static int server_handle_disconnect(struct run_ctx *ctx,
				    struct rdma_cm_id *child_id)
{
	struct rdma_connection *q;

	if (!ctx)
		return -EINVAL;

	q = child_id->context;

	printf("%s q = %p, recv count = %d\n", __func__, q, q->rx.recv_cnt);
	return 0;
}

static int setup_server(struct run_ctx *ctx)
{
	struct rdma_cm_event *event;
	struct sockaddr_in addr_in;
	struct rdma_cm_id *child_id;
	int ret;

	ret = rdma_create_id(ctx->r_ctx.channel, &ctx->r_ctx.listen_cm_id, NULL, 
			     RDMA_PS_TCP);
	if (ret)
		return ret;

	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(ctx->port);
	addr_in.sin_addr.s_addr = htonl(INADDR_ANY);

	ret = rdma_bind_addr(ctx->r_ctx.listen_cm_id, (struct sockaddr *)&addr_in);
	if (ret)
		return ret;

	ret = rdma_listen(ctx->r_ctx.listen_cm_id, 1024);
	if (ret)
		return ret;

	while (1) {
		event = wait_for_event(ctx);
		if (!event)
			break;

		child_id = ctx->r_ctx.event->id;
		switch (event->event) {
		case RDMA_CM_EVENT_CONNECT_REQUEST:
			ret = rdma_ack_event(ctx);
			ret = server_handle_connect(ctx, child_id);
			break;
		case RDMA_CM_EVENT_ESTABLISHED:
			ret = rdma_ack_event(ctx);
			break;
		case RDMA_CM_EVENT_DISCONNECTED:
			ret = server_handle_disconnect(ctx, child_id);
			ret = rdma_ack_event(ctx);
			break;
		default:
			ret = rdma_ack_event(ctx);
			break;
		}
	}

	printf("%s status = %d\n", __func__, ret);
	return ret;
}

static int rdmacm_client_cm_event_handler(struct rdma_cm_id *cm_id,
					  struct rdma_cm_event *event)
{
	struct rdma_connection *q = cm_id->context;
	struct rdmacm_client_ctx *c_ctx;

	printf("%s q = %p\n", __func__, q);

	c_ctx = q->c_ctx;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		q->state = RDMAIO_CM_STATE_ADDR_RESOLVED;
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		q->state = RDMAIO_CM_STATE_ROUTE_RESOLVED;
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		q->state = RDMAIO_CM_CONNECTED;
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		q->state = RDMAIO_CM_DISCONNECTED;
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		q->state = RDMAIO_CM_DISCONNECTED;
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		q->state = RDMAIO_CM_FATAL_ERROR;
		break;
	default:
		fprintf(stderr, "unknown event: %s\n",
			rdma_event_str(event->event));
		break;
	}
	sem_post(&c_ctx->sem);
	return 0;
}

static void* client_cm_thread(void *arg)
{
	struct run_ctx *ctx = arg;
	struct rdma_cm_event *event;

	while (1) {
		event = wait_for_event(ctx);
		if (!event)
			continue;

		rdmacm_client_cm_event_handler(event->id, event);
		rdma_ack_event(ctx);
	}
	return NULL;
}

static int client_setup_cm_thread(struct run_ctx *ctx)
{
	int ret;

	ret = pthread_create(&ctx->r_ctx.c_ctx.cm_thread, NULL,
			     client_cm_thread, ctx);
	return ret;
}

static int setup_tx_cmds_buffers(struct rdma_connection *q,
				 int cmd_size, int cmd_count)
{
	q->tx.cmds = calloc(cmd_count, cmd_size);
	if (!q->tx.cmds)
		return -ENOMEM;

	memset(q->tx.cmds, 0, cmd_size * cmd_count);

	q->tx.cmds_mr = ibv_reg_mr(q->pd, q->tx.cmds,
				       cmd_size * cmd_count,
				       IBV_ACCESS_LOCAL_WRITE);
	if (!q->tx.cmds_mr)
		return -ENOMEM;


	q->tx.wrs = calloc(cmd_count, sizeof(*q->tx.wrs));
	if (!q->tx.wrs)
		return -ENOMEM;

	return 0;
}

static void init_tx_cmd_wrs(struct rdma_connection *q,
			    int cmd_size, int cmd_count)
{
	int i;

	for (i = 0; i < cmd_count; i++) {
		q->tx.wrs[i].cmd = &q->tx.cmds[i];
		q->tx.wrs[i].sge.addr = (uintptr_t)&q->tx.cmds[i];
		q->tx.wrs[i].sge.length = cmd_size;
		q->tx.wrs[i].sge.lkey = q->tx.cmds_mr->lkey;

		q->tx.wrs[i].send_wr.wr_id = (uintptr_t)q->tx.wrs[i].cmd;
		q->tx.wrs[i].send_wr.sg_list = &q->tx.wrs[i].sge;
		q->tx.wrs[i].send_wr.num_sge = 1;

		q->tx.wrs[i].send_wr.opcode = IBV_WR_SEND;
		q->tx.wrs[i].send_wr.send_flags = IBV_SEND_SIGNALED;
	}
}

static int rdmaio_post_send_wr(struct rdma_connection *q, int index)
{
	struct ibv_send_wr *bad_wr;
	int ret;

	ret = ibv_post_send(q->cm_id->qp, &q->tx.wrs[index].send_wr,
			    &bad_wr);
	return ret;
}

static void setup_path_record(struct ibv_path_data *out,
			     struct ibv_sa_path_rec *cached)
{
	memset(out, 0, sizeof(*out));

	out->flags = IBV_PATH_FLAG_PRIMARY | IBV_PATH_FLAG_GMP |
		     IBV_PATH_FLAG_BIDIRECTIONAL;
	out->path.service_id = 0;
	out->path.dgid = cached->dgid;
	out->path.sgid = cached->sgid;
	out->path.flowlabel_hoplimit = 0xff;
	out->path.reversible_numpath = (1 << 7) | 0x1; /* reversible-7:7 num path-6:0 */
	out->path.pkey = 0xffff;
	out->path.mtu = (cached->mtu_selector << 6) | cached->mtu;
	out->path.packetlifetime =
		(cached->packet_life_time_selector << 6) || cached->packet_life_time;
	out->path.preference = cached->preference;
}

static int client_send_cmds(struct rdma_connection *q, int cmd_size, int cmd_count)
{
	int ret;
	int i;

	init_tx_cmd_wrs(q, cmd_size, cmd_count);

	for (i = 0; i < cmd_count; i++) {
		ret = rdmaio_post_send_wr(q, i);
		if (ret)
			break;
	}

	printf("%s i= %d ret = %d\n", __func__, i, ret);
	return ret;
}

static int client_setup_one_connection(struct run_ctx *ctx)
{
	struct rdma_conn_param conn_param;
	struct rdma_connection *q; 
	struct sockaddr_in *in4;
	int ret;

	q = alloc_q(ctx);
	if (!q)
		return -ENOMEM;

	ret = rdma_create_id(ctx->r_ctx.channel, &q->cm_id, NULL, 
			     RDMA_PS_TCP);
	if (ret)
		return ret;
	q->c_ctx = &ctx->r_ctx.c_ctx;
	q->cm_id->context = q;

	in4 = (struct sockaddr_in *)&ctx->sockaddr;
	in4->sin_family = AF_INET;
	in4->sin_port = htons(ctx->port);
	if (ctx->src_sockaddr.ss_family) 
		ret = rdma_resolve_addr(q->cm_id,
				(struct sockaddr *)&ctx->src_sockaddr,
				(struct sockaddr *)&ctx->sockaddr, 5000);
	else
		ret = rdma_resolve_addr(q->cm_id,
				NULL,
				(struct sockaddr *)&ctx->sockaddr, 5000);
	if (ret) {
		perror("rdma_resolve_addr");
		return ret;
	}
	sem_wait(&ctx->r_ctx.c_ctx.sem);
	if (q->state != RDMAIO_CM_STATE_ADDR_RESOLVED)
		return -EINVAL;

	/* Check if route resolve needs to be skipped for multiple
	 * connections.
	 * First connection needs to have the route resolved to reuse
	 * for subsequent connections.
	 */
	if (!ctx->skip_route_resolve || !q->id) {
		printf("%s resolving route q = %p\n", __func__, q);
		ret = rdma_resolve_route(q->cm_id, 5000);
		if (ret) {
			q->state = RDMAIO_CM_FATAL_ERROR;
			perror("rdma_resolve_route");
		}
	} else {
		struct ibv_path_data path_record;
		printf("num paths for first connection=%d\n",
			ctx->r_ctx.clients[0].cm_id->route.num_paths);

		setup_path_record(&path_record,
				  &ctx->r_ctx.clients[0].cm_id->route.path_rec[0]);

		printf("%s setting options q = %p\n", __func__, q);

		ret = rdma_set_option(q->cm_id, RDMA_OPTION_IB,
				      RDMA_OPTION_IB_PATH,
				      &path_record,
				      sizeof(path_record));
		if (ret) {
			printf("%s fail to set path record option ret = %d\n", __func__, ret);
			return ret;
		}
	}
	sem_wait(&ctx->r_ctx.c_ctx.sem);
	if (q->state != RDMAIO_CM_STATE_ROUTE_RESOLVED) {
		printf("%s q = %p, state = %d\n", __func__, q, q->state);
		return -EINVAL;
	}

	printf("%s creating q =%p\n", __func__, q);
	ret = create_q(q);
	if (ret) {
		printf("%s fail to create q = %d\n", __func__, ret);
		return ret;
	}

	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = 7;

	ret = rdma_connect(q->cm_id, &conn_param);
	if (ret) {
		printf("%s fail to connect ret = %d\n", __func__, ret);
		return ret;
	}
	sem_wait(&ctx->r_ctx.c_ctx.sem);
	if (q->state != RDMAIO_CM_CONNECTED)
		return -EINVAL;
	
	ret = setup_tx_cmds_buffers(q, sizeof(struct rdmaio_cmd),
				    RDMAIO_Q_DEPTH);
	if (ret)
		return ret;

	ret = client_send_cmds(q, sizeof(struct rdmaio_cmd),
			       RDMAIO_Q_DEPTH);
	return ret;
}

static int setup_client(struct run_ctx *ctx)
{
	int ret;
	int i;

	sem_init(&ctx->r_ctx.c_ctx.sem, 0, 0);

	ret = client_setup_cm_thread(ctx);
	if (ret)
		return ret;

	for (i = 0; i < ctx->connections; i++) {
		ret = client_setup_one_connection(ctx);
		if (ret)
			break;
	}

	return ret;
}

static int setup_test(struct run_ctx *ctx)
{
	int err = 0;

	err = alloc_mem(ctx);
	if (err) {
		fprintf(stderr, "Couldn't allocate memory of size %ld\n",
			ctx->size);
		err = -ENODEV;
		goto err;
	}
	ctx->r_ctx.channel = rdma_create_event_channel();
	if (!ctx->r_ctx.channel) {
		err = -ENODEV;
		goto err;
	}
	ctx->access_flags = IBV_ACCESS_LOCAL_WRITE;
	if (ctx->odp)
		ctx->access_flags |= IBV_ACCESS_ON_DEMAND;

	if (ctx->server) {
		err = setup_server(ctx);
		if (err)
			goto err;
	} else {
		err = setup_client(ctx);
		if (err)
			goto err;
	}

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
	if (ctx)
		free_mem(ctx);
}

int main(int argc, char **argv)
{
	struct run_ctx *ctx;
	int err;

	setvbuf(stdout, NULL, _IOLBF, 0);

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		err = -ENOMEM;
		goto err;
	}
	ctx->size = sysconf(_SC_PAGESIZE);
	ctx->page_size = sysconf(_SC_PAGESIZE);
	ctx->align = sysconf(_SC_PAGESIZE);
	ctx->count = 1;
	ctx->connections = 1;

	parse_options(ctx, argc, argv);

	err = setup_test(ctx);
	if (err)
		goto err;

	cleanup_test(ctx);
	return 0;

err:
	cleanup_test(ctx);
	return err;
}
