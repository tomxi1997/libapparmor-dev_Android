/*
 * Copyright (C) 2022 Canonical, Ltd.
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

#define _GNU_SOURCE
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

static void usage(char *pname)
{
	fprintf(stderr, "Usage: %s [options]\n", pname);
	fprintf(stderr, "Options can be:\n");
	fprintf(stderr, "    -c   create user namespace using clone\n");
	fprintf(stderr, "    -u   create user namespace using unshare\n");
	exit(EXIT_FAILURE);
}

#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];

static int child(void *arg)
{
	return EXIT_SUCCESS;
}

int userns_unshare()
{
	if (unshare(CLONE_NEWUSER) == -1) {
		perror("FAIL - unshare");
		return EXIT_FAILURE;
	}
	return child(NULL);
}

int userns_clone()
{
	pid_t child_pid;
	int child_exit;

	child_pid = clone(child, child_stack + STACK_SIZE,
			  CLONE_NEWUSER | SIGCHLD, NULL);
	if (child_pid == -1) {
		perror("FAIL - clone");
		return EXIT_FAILURE;
	}

	if (waitpid(child_pid, &child_exit, 0) == -1) {
		perror("FAIL - waitpid");
		return EXIT_FAILURE;
	}

	if (WIFEXITED(child_exit)) {
		if (WEXITSTATUS(child_exit) != EXIT_SUCCESS) {
			fprintf(stderr, "FAIL - child ended with failure %d\n", child_exit);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

enum op {
	CLONE,
	UNSHARE,
};

int main(int argc, char *argv[])
{
	int opt, ret = 0, op;

	while ((opt = getopt(argc, argv, "uc")) != -1) {
		switch (opt) {
		case 'c': op = CLONE;	break;
		case 'u': op = UNSHARE;	break;
		default:  usage(argv[0]);
		}
	}

	if (op == CLONE)
		ret = userns_clone();
	else if (op == UNSHARE)
		ret = userns_unshare();
	else
		fprintf(stderr, "FAIL - user namespace method not defined\n");

	if (ret == EXIT_SUCCESS)
		printf("PASS\n");
	return ret;
}
