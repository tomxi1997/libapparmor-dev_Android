/*
 * Copyright (C) 2023 Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, contact Canonical Ltd.
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <liburing.h>

#define DEFAULT_FILENAME "/tmp/io_uring_test"
#define DEFAULT_UID 1000

static int no_personality;

static int open_file(struct io_uring *ring, int cred_id, char *filename)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret, i, to_submit = 1;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "FAIL - could not get sqe.\n");
		return 1;
	}
	io_uring_prep_openat(sqe, -1, filename, O_RDONLY, 0);
	sqe->user_data = 1;

	if (cred_id != -1)
		sqe->personality = cred_id;

	ret = io_uring_submit(ring);
	if (ret != to_submit) {
		fprintf(stderr, "FAIL - could not submit: %s\n", strerror(-ret));
		goto err;
	}

	for (i = 0; i < to_submit; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "FAIL - wait cqe failed %s\n", strerror(-ret));
			goto err;
		}

		ret = cqe->res;
		io_uring_cqe_seen(ring, cqe);
	}
err:
	return ret;
}

static int test_personality(struct io_uring *ring, char *filename, uid_t uid)
{
	int ret, cred_id;
	ret = io_uring_register_personality(ring);
	if (ret < 0) {
		if (ret == -EINVAL) {
			no_personality = 1;
			goto out;
		}
		fprintf(stderr, "FAIL - could not register personality: %s\n", strerror(-ret));
		goto err;
	}
	cred_id = ret;

	/* create file only owner can open */
	ret = open(filename, O_RDONLY | O_CREAT, 0600);
	if (ret < 0) {
		perror("open");
		goto err;
	}
	close(ret);

	/* verify we can open it */
	ret = open_file(ring, -1, filename);
	if (ret < 0) {
		fprintf(stderr, "FAIL - root could not open file: %d\n", ret);
		goto err;
	}

	if (seteuid(uid) < 0) {
		fprintf(stdout, "FAIL - could not switch to uid %u\n", uid);
		goto out;
	}

	/* verify we can't open it with current credentials */
	ret = open_file(ring, -1, filename);
	if (ret != -EACCES) {
		fprintf(stderr, "FAIL - opened with regular credential: %d\n", ret);
		goto err;
	}

	/* verify we can open with registered credentials */
	ret = open_file(ring, cred_id, filename);
	if (ret < 0) {
		fprintf(stderr, "FAIL - could not open with registered credentials: %d\n", ret);
		goto err;
	}
	close(ret);

	if (seteuid(0))
		perror("FAIL - seteuid");

	ret = io_uring_unregister_personality(ring, cred_id);
	if (ret) {
		fprintf(stderr, "FAIL - could not unregister personality: %s\n",
			strerror(-ret));
		goto err;
	}

out:
	unlink(filename);
	return 0;
err:
	unlink(filename);
	return 1;
}

static void usage(char *pname)
{
	fprintf(stderr, "Usage: %s [options]\n", pname);
	fprintf(stderr, "Options can be:\n");
	fprintf(stderr, "    -s   create ring using IORING_SETUP_SQPOLL\n");
	fprintf(stderr, "    -o   use io_uring personality to open a file\n");
	fprintf(stderr, "    -u   specify UID for option -s (default is %d)\n", DEFAULT_UID);
	fprintf(stderr, "    -f   specify file opened by option -s (default is %s)\n", DEFAULT_FILENAME);
	exit(EXIT_FAILURE);
}

enum op {
	SQPOLL,
	OVERRIDE_CREDS,
	INVALID_OP,
};

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int opt, ret = 0, op = INVALID_OP;
	char *filename = DEFAULT_FILENAME;
	uid_t uid = DEFAULT_UID;

	while ((opt = getopt(argc, argv, "sou:f:")) != -1) {
		switch (opt) {
		case 's': op = SQPOLL;	break;
		case 'o': op = OVERRIDE_CREDS; break;
		case 'u': uid = atoi(optarg); break;
		case 'f': filename = optarg; break;
		default:  usage(argv[0]);
		}
	}

	if (op == INVALID_OP) {
		printf("FAIL - operation not selected\n");
		return 1;
	}

	if (op == SQPOLL) {
		ret = io_uring_queue_init(8, &ring, IORING_SETUP_SQPOLL);
		if (ret) {
			fprintf(stderr, "FAIL - failed to create sqpoll ring: %s\n",
				strerror(-ret));
			return 1;
		}
		io_uring_queue_exit(&ring);
	}

	if (op == OVERRIDE_CREDS) {
		ret = io_uring_queue_init(8, &ring, 0);
		if (ret) {
			fprintf(stderr, "FAIL - failed to create override_creds ring: %s\n",
				strerror(-ret));
			return 1;
		}

		ret = test_personality(&ring, filename, uid);
		if (no_personality) {
			/* personality was added in kernel 5.6 */
			printf("Personalities not supported, skipping...\n");
		} else if (ret) {
			fprintf(stderr, "FAIL - override_creds failed\n");
			return ret;
		}
		io_uring_queue_exit(&ring);
	}

	printf("PASS\n");
	return 0;
}
