/*
 * Helper that uses io_uring to write content to a file.
 * All I/O (open, write, close) goes through io_uring,
 * bypassing the normal syscall path.
 *
 * Usage: io_uring_write <file> <content>
 *
 * Exit codes:
 *   0 - success
 *   1 - usage error
 *   2 - io_uring not available
 *   3 - I/O error
 */
#include <fcntl.h>
#include <liburing.h>
#include <stdio.h>
#include <string.h>

static int submit_wait(struct io_uring *ring, const char *op)
{
	struct io_uring_cqe *cqe;
	int ret;

	io_uring_submit(ring);
	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait %s: %s\n", op, strerror(-ret));
		return ret;
	}
	ret = cqe->res;
	if (ret < 0)
		fprintf(stderr, "%s: %s\n", op, strerror(-ret));
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	struct io_uring_sqe *sqe;
	int result = 3, ret, fd;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <file> <content>\n", argv[0]);
		return 1;
	}

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret < 0) {
		fprintf(stderr, "io_uring_queue_init: %s\n", strerror(-ret));
		return 2;
	}

	/* Open file via io_uring */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_openat(sqe, AT_FDCWD, argv[1], O_WRONLY | O_TRUNC, 0);
	fd = submit_wait(&ring, "openat");
	if (fd < 0)
		goto err;

	/* Write content via io_uring */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_write(sqe, fd, argv[2], strlen(argv[2]), 0);
	ret = submit_wait(&ring, "write");
	if (ret < 0)
		goto err;

	/* Close file via io_uring */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_close(sqe, fd);
	ret = submit_wait(&ring, "close");
	if (ret < 0)
		goto err;

	result = 0;
err:
	io_uring_queue_exit(&ring);
	return result;
}
