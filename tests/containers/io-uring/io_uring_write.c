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

int main(int argc, char *argv[])
{
	struct io_uring ring;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret, fd;

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
	io_uring_submit(&ring);
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait openat: %s\n", strerror(-ret));
		goto err;
	}
	if (cqe->res < 0) {
		fprintf(stderr, "openat: %s\n", strerror(-cqe->res));
		io_uring_cqe_seen(&ring, cqe);
		goto err;
	}
	fd = cqe->res;
	io_uring_cqe_seen(&ring, cqe);

	/* Write content via io_uring */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_write(sqe, fd, argv[2], strlen(argv[2]), 0);
	io_uring_submit(&ring);
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait write: %s\n", strerror(-ret));
		goto err;
	}
	if (cqe->res < 0) {
		fprintf(stderr, "write: %s\n", strerror(-cqe->res));
		io_uring_cqe_seen(&ring, cqe);
		goto err;
	}
	io_uring_cqe_seen(&ring, cqe);

	/* Close file via io_uring */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_close(sqe, fd);
	io_uring_submit(&ring);
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait close: %s\n", strerror(-ret));
		goto err;
	}
	io_uring_cqe_seen(&ring, cqe);

	io_uring_queue_exit(&ring);
	return 0;

err:
	io_uring_queue_exit(&ring);
	return 3;
}
