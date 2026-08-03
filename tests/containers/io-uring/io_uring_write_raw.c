/*
 * Helper that uses raw io_uring syscalls to write content to a file.
 * No liburing dependency — only uses io_uring_setup/io_uring_enter
 * syscalls directly, so it can be statically linked.
 *
 * Usage: io_uring_write_raw <file> <content>
 *
 * Exit codes:
 *   0 - success
 *   1 - usage error
 *   2 - io_uring not available
 *   3 - I/O error
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

struct ring {
	int fd;
	struct io_uring_sqe *sqes;
	unsigned *sq_tail;
	unsigned *sq_mask;
	unsigned *sq_array;
	struct io_uring_cqe *cqes;
	unsigned *cq_head;
	unsigned *cq_tail;
	unsigned *cq_mask;
};

static int ring_init(struct ring *r, unsigned entries)
{
	struct io_uring_params p;

	memset(&p, 0, sizeof(p));

	int fd = syscall(__NR_io_uring_setup, entries, &p);
	if (fd < 0)
		return -1;

	size_t sq_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
	size_t cq_sz = p.cq_off.cqes +
		       p.cq_entries * sizeof(struct io_uring_cqe);
	size_t sqe_sz = p.sq_entries * sizeof(struct io_uring_sqe);

	void *sq = mmap(NULL, sq_sz, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
	void *cq = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
	void *sqes = mmap(NULL, sqe_sz, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);

	if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED) {
		close(fd);
		return -1;
	}

	r->fd = fd;
	r->sqes = sqes;
	r->sq_tail = sq + p.sq_off.tail;
	r->sq_mask = sq + p.sq_off.ring_mask;
	r->sq_array = sq + p.sq_off.array;
	r->cqes = cq + p.cq_off.cqes;
	r->cq_head = cq + p.cq_off.head;
	r->cq_tail = cq + p.cq_off.tail;
	r->cq_mask = cq + p.cq_off.ring_mask;

	return 0;
}

static struct io_uring_sqe *get_sqe(struct ring *r)
{
	unsigned tail = __atomic_load_n(r->sq_tail, __ATOMIC_RELAXED);
	unsigned idx = tail & *r->sq_mask;
	struct io_uring_sqe *sqe = &r->sqes[idx];

	memset(sqe, 0, sizeof(*sqe));
	return sqe;
}

static int submit_and_wait(struct ring *r, struct io_uring_cqe **cqe)
{
	unsigned tail = __atomic_load_n(r->sq_tail, __ATOMIC_RELAXED);
	unsigned idx = tail & *r->sq_mask;

	r->sq_array[idx] = idx;
	__atomic_store_n(r->sq_tail, tail + 1, __ATOMIC_RELEASE);

	int ret = syscall(__NR_io_uring_enter, r->fd, 1, 1,
			  IORING_ENTER_GETEVENTS, NULL, 0);
	if (ret < 0)
		return -1;

	unsigned head = __atomic_load_n(r->cq_head, __ATOMIC_RELAXED);

	*cqe = &r->cqes[head & *r->cq_mask];
	return 0;
}

static void cqe_advance(struct ring *r)
{
	unsigned head = __atomic_load_n(r->cq_head, __ATOMIC_RELAXED);

	__atomic_store_n(r->cq_head, head + 1, __ATOMIC_RELEASE);
}

int main(int argc, char *argv[])
{
	struct ring r;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <file> <content>\n", argv[0]);
		return 1;
	}

	if (ring_init(&r, 4) < 0) {
		fprintf(stderr, "io_uring_setup: %s\n", strerror(errno));
		return 2;
	}

	/* Open file via io_uring */
	sqe = get_sqe(&r);
	sqe->opcode = IORING_OP_OPENAT;
	sqe->fd = AT_FDCWD;
	sqe->addr = (unsigned long)argv[1];
	sqe->open_flags = O_WRONLY | O_TRUNC;
	if (submit_and_wait(&r, &cqe) < 0 || cqe->res < 0) {
		fprintf(stderr, "openat: %s\n",
			strerror(-(cqe ? cqe->res : errno)));
		return 3;
	}
	int fd = cqe->res;
	cqe_advance(&r);

	/* Write content via io_uring */
	sqe = get_sqe(&r);
	sqe->opcode = IORING_OP_WRITE;
	sqe->fd = fd;
	sqe->addr = (unsigned long)argv[2];
	sqe->len = strlen(argv[2]);
	if (submit_and_wait(&r, &cqe) < 0 || cqe->res < 0) {
		fprintf(stderr, "write: %s\n",
			strerror(-(cqe ? cqe->res : errno)));
		return 3;
	}
	cqe_advance(&r);

	/* Close file via io_uring */
	sqe = get_sqe(&r);
	sqe->opcode = IORING_OP_CLOSE;
	sqe->fd = fd;
	if (submit_and_wait(&r, &cqe) < 0 || cqe->res < 0) {
		fprintf(stderr, "close: %s\n",
			strerror(-(cqe ? cqe->res : errno)));
		return 3;
	}
	cqe_advance(&r);

	close(r.fd);
	return 0;
}
