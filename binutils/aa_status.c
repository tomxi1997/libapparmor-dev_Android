/*
 *   Copyright (C) 2020 Canonical Ltd.
 *
 *   This program is free software; you can redistribute it and/or
 *    modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 */

#define _GNU_SOURCE /* for asprintf() */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>

#include <sys/apparmor.h>
#include <sys/apparmor_private.h>

#include "cJSON.h"

#define autofree __attribute((cleanup(_aa_autofree)))
#define autofclose __attribute((cleanup(_aa_autofclose)))

#define AA_EXIT_ENABLED 0
#define AA_EXIT_DISABLED 1
#define AA_EXIT_NO_POLICY 2
#define AA_EXIT_NO_CONTROL 3
#define AA_EXIT_NO_PERM 4
#define AA_EXIT_INTERNAL_ERROR 42

/* NOTE: Increment this whenever the JSON format changes */
static const unsigned char aa_status_json_version[] = "2";

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define __unused __attribute__ ((__unused__))

struct profile {
	char *name;
	char *status;
};

static void free_profiles(struct profile *profiles, size_t n) {
	while (n > 0) {
		n--;
		free(profiles[n].name);
		free(profiles[n].status);
	}
	free(profiles);
}

struct process {
	char *pid;
	char *profile;
	char *exe;
	char *mode;
};

static void free_processes(struct process *processes, size_t n) {
	while (n > 0) {
		n--;
		free(processes[n].pid);
		free(processes[n].profile);
		free(processes[n].exe);
		free(processes[n].mode);
	}
	free(processes);
}

static int verbose = 0;

#define dprintf(...)                                                           \
do {									       \
	if (verbose)							       \
		printf(__VA_ARGS__);					       \
} while (0)

#define dfprintf(...)                                                          \
do {									       \
	if (verbose)							       \
		fprintf(__VA_ARGS__);					       \
} while (0)


/**
 * get_profiles - get a listing of profiles on the system
 * @profiles: return: list of profiles
 * @n: return: number of elements in @profiles
 *
 * Return: 0 on success, shell error on failure
 */
static int get_profiles(struct profile **profiles, size_t *n) {
	autofree char *apparmorfs = NULL;
	autofree char *apparmor_profiles = NULL;
	struct stat st;
	autofclose FILE *fp = NULL;
	autofree char *line = NULL;
	size_t len = 0;
	int ret;

	*profiles = NULL;
	*n = 0;

	ret = stat("/sys/module/apparmor", &st);
	if (ret != 0) {
		dfprintf(stderr, "apparmor not present.\n");
		ret = AA_EXIT_DISABLED;
		goto exit;
	}
	dprintf("apparmor module is loaded.\n");

	ret = aa_find_mountpoint(&apparmorfs);
	if (ret == -1) {
		dfprintf(stderr, "apparmor filesystem is not mounted.\n");
		ret = AA_EXIT_NO_CONTROL;
		goto exit;
	}

	apparmor_profiles = malloc(strlen(apparmorfs) + 10); // /profiles\0
	if (apparmor_profiles == NULL) {
		ret = AA_EXIT_INTERNAL_ERROR;
		goto exit;
	}
	sprintf(apparmor_profiles, "%s/profiles", apparmorfs);

	fp = fopen(apparmor_profiles, "r");
	if (fp == NULL) {
		if (errno == EACCES) {
			dfprintf(stderr, "You do not have enough privilege to read the profile set.\n");
		} else {
			dfprintf(stderr, "Could not open %s: %s", apparmor_profiles, strerror(errno));
		}
		ret = AA_EXIT_NO_PERM;
		goto exit;
	}

	while (getline(&line, &len, fp) != -1) {
		struct profile *_profiles;
		autofree char *status = NULL;
		autofree char *name = NULL;
		char *tmpname = aa_splitcon(line, &status);

		if (!tmpname) {
			dfprintf(stderr, "Error: failed profile name split of '%s'.\n", line);
			ret = AA_EXIT_INTERNAL_ERROR;
			// skip this entry and keep processing
			continue;
		}
		name = strdup(tmpname);

		if (status)
			status = strdup(status);
		// give up if out of memory
		if (name == NULL || status == NULL) {
			free_profiles(*profiles, *n);
			*profiles = NULL;
			*n = 0;
			ret = AA_EXIT_INTERNAL_ERROR;
			break;
		}
		_profiles = realloc(*profiles, (*n + 1) * sizeof(**profiles));
		if (_profiles == NULL) {
			free_profiles(*profiles, *n);
			*profiles = NULL;
			*n = 0;
			ret = AA_EXIT_INTERNAL_ERROR;
			break;
		}
		// steal name and status
		_profiles[*n].name = name;
		_profiles[*n].status = status;
		name = NULL;
		status = NULL;
		*n = *n + 1;
		*profiles = _profiles;
	}

exit:
	return ret == 0 ? (*n > 0 ? AA_EXIT_ENABLED : AA_EXIT_NO_POLICY) : ret;
}

static int compare_profiles(const void *a, const void *b) {
	return strcmp(((struct profile *)a)->name,
		      ((struct profile *)b)->name);
}

/**
 * filter_profiles - create a filtered profile list
 * @profiles: list of profiles
 * @n: number of elements in @profiles
 * @filter: string to match against profile mode, if NULL no filter
 * @filtered: return: new list of profiles that match the filter
 * @nfiltered: return: number of elements in @filtered
 *
 * Return: 0 on success, shell error on failure
 */
static int filter_profiles(struct profile *profiles,
			   size_t n,
			   const char *filter,
			   struct profile **filtered,
			   size_t *nfiltered)
{
	int ret = 0;
	size_t i;

	*filtered = NULL;
	*nfiltered = 0;

	for (i = 0; i < n; i++) {
		if (filter == NULL || strcmp(profiles[i].status, filter) == 0) {
			struct profile *_filtered = realloc(*filtered, (*nfiltered + 1) * sizeof(**filtered));
			if (_filtered == NULL) {
				free_profiles(*filtered, *nfiltered);
				*filtered = NULL;
				*nfiltered = 0;
				ret = AA_EXIT_INTERNAL_ERROR;
				break;
			}
			_filtered[*nfiltered].name = strdup(profiles[i].name);
			_filtered[*nfiltered].status = strdup(profiles[i].status);
			*filtered = _filtered;
			*nfiltered = *nfiltered + 1;
		}
	}
	if (*nfiltered != 0) {
		qsort(*filtered, *nfiltered, sizeof(*profiles), compare_profiles);
	}
	return ret;
}

/**
 * get_processes - get a list of processes that are confined
 * @profiles: list of profiles, used to filter out unconfined processes
 * @n: number of entries in @procfiles
 * @processes: return: list of confined processes
 * @nprocesses: return: number of entries in @processes
 *
 * Return: 0 on success, shell exit code on failure
 *
 * profiles is used to find prcesses that should be confined but aren't.
 */
static int get_processes(struct profile *profiles,
			 size_t n,
			 struct process **processes,
			 size_t *nprocesses)
{
	DIR *dir = NULL;
	struct dirent *entry = NULL;
	int ret = 0;

	*processes = NULL;
	*nprocesses = 0;

	dir = opendir("/proc");
	if (dir == NULL) {
		ret = AA_EXIT_INTERNAL_ERROR;
		goto exit;
	}
	while ((entry = readdir(dir)) != NULL) {
		size_t i;
		int rc;
		int ispid = 1;
		autofree char *profile = NULL;
		autofree char *mode = NULL; /* be careful */
		autofree char *exe = NULL;
		autofree char *real_exe = NULL;
		autofclose FILE *fp = NULL;
		autofree char *line = NULL;

		// ignore non-pid entries
		for (i = 0; ispid && i < strlen(entry->d_name); i++) {
			ispid = (isdigit(entry->d_name[i]) ? 1 : 0);
		}
		if (!ispid) {
			continue;
		}

		rc = aa_getprocattr(atoi(entry->d_name), "current", &profile, &mode);
		if (rc == -1 && errno != ENOMEM) {
			/* fail to access */
			continue;
		} else if (rc == -1 ||
			   asprintf(&exe, "/proc/%s/exe", entry->d_name) == -1) {
			fprintf(stderr, "ERROR: Failed to allocate memory\n");
			ret = AA_EXIT_INTERNAL_ERROR;
			goto exit;
		} else if (mode) {
			/* TODO: make this not needed. Mode can now be autofreed */
			mode = strdup(mode);
		}
		// get executable - readpath can allocate for us but seems
		// to fail in some cases with errno 2 - no such file or
		// directory - whereas readlink() can succeed in these
		// cases - and readpath() seems to have the same behaviour
		// as in python with better canonicalized results so try it
		// first and fallack to readlink if it fails
		// coverity[toctou]
		real_exe = realpath(exe, NULL);
		if (real_exe == NULL) {
			int res;
			// ensure enough space for NUL terminator
			real_exe = calloc(PATH_MAX + 1, sizeof(char));
			if (real_exe == NULL) {
				fprintf(stderr, "ERROR: Failed to allocate memory\n");
				ret = AA_EXIT_INTERNAL_ERROR;
				goto exit;
			}
			res = readlink(exe, real_exe, PATH_MAX);
			if (res == -1) {
				continue;
			}
			real_exe[res] = '\0';
		}


		if (mode == NULL) {
			// is unconfined so keep only if this has a
			// matching profile. TODO: fix to use attachment
			// ideally would walk process tree and apply
			// according to x rules and attachments
			for (i = 0; i < n; i++) {
				if (strcmp(profiles[i].name, real_exe) == 0) {
					profile = strdup(real_exe);
					mode = strdup("unconfined");
					break;
				}
			}
		}
		if (profile != NULL && mode != NULL) {
			struct process *_processes = realloc(*processes,
							     (*nprocesses + 1) * sizeof(**processes));
			if (_processes == NULL) {
				free_processes(*processes, *nprocesses);
				*processes = NULL;
				*nprocesses = 0;
				ret = AA_EXIT_INTERNAL_ERROR;
				goto exit;
			}
			_processes[*nprocesses].pid = strdup(entry->d_name);
			_processes[*nprocesses].profile = profile;
			_processes[*nprocesses].exe = strdup(real_exe);
			_processes[*nprocesses].mode = mode;
			*processes = _processes;
			*nprocesses = *nprocesses + 1;
			profile = NULL;
			mode = NULL;
			ret = AA_EXIT_ENABLED;
		}
	}

exit:
	if (dir != NULL) {
		closedir(dir);
	}
	return ret;
}

/**
 * filter_processes: create a new filtered process list by applying @filter
 * @processes: list of processes to filter
 * @n: number of entries in @processes
 * @filter: mode string to filter @processes against, if NULL no filter
 * @filtered: return: new list of processes matching filter
 * @nfiltered: number of entries in @filtered
 *
 * Return: 0 on success, shell exit value on failure
 */
static int filter_processes(struct process *processes,
			    size_t n,
			    const char *filter,
			    struct process **filtered,
			    size_t *nfiltered)
{
	size_t i;
	int ret = 0;

	*filtered = NULL;
	*nfiltered = 0;

	for (i = 0; i < n; i++) {
		if (filter == NULL || strcmp(processes[i].mode, filter) == 0) {
			struct process *_filtered = realloc(*filtered, (*nfiltered + 1) * sizeof(**filtered));
			if (_filtered == NULL) {
				free_processes(*filtered, *nfiltered);
				*filtered = NULL;
				*nfiltered = 0;
				ret = AA_EXIT_INTERNAL_ERROR;
				break;
			}
			_filtered[*nfiltered].pid = strdup(processes[i].pid);
			_filtered[*nfiltered].profile = strdup(processes[i].profile);
			_filtered[*nfiltered].exe = strdup(processes[i].exe);
			_filtered[*nfiltered].mode = strdup(processes[i].mode);
			*filtered = _filtered;
			*nfiltered = *nfiltered + 1;
		}
	}

	return ret;
}

/**
 * simple_filtered_count - count the number of profiles with mode == filter
 * @outf: output file destination
 * @filter: mode string to filter profiles on
 *
 * Return: 0 on success, else shell error code
 */
static int simple_filtered_count(FILE *outf, const char *filter) {
	size_t n;
	struct profile *profiles;
	int ret;

	ret = get_profiles(&profiles, &n);
	if (ret == 0) {
		size_t nfiltered;
		struct profile *filtered = NULL;
		ret = filter_profiles(profiles, n, filter, &filtered, &nfiltered);
		fprintf(outf, "%zd\n", nfiltered);
		free_profiles(filtered, nfiltered);
	}
	free_profiles(profiles, n);
	return ret;
}

/**
 * simple_filtered_process_count - count processes with mode == filter
 * @outf: output file destination
 * @filter: mode string to filter processes on
 *
 * Return: 0 on success, else shell error code
 */
static int simple_filtered_process_count(FILE *outf, const char *filter) {
	size_t nprocesses, nprofiles;
	struct profile *profiles = NULL;
	struct process *processes = NULL;
	int ret;

	ret = get_profiles(&profiles, &nprofiles);
	if (ret != 0)
		return ret;
	ret = get_processes(profiles, nprofiles, &processes, &nprocesses);
	if (ret == 0) {
		size_t nfiltered;
		struct process *filtered = NULL;
		ret = filter_processes(processes, nprocesses, filter, &filtered, &nfiltered);
		fprintf(outf, "%zd\n", nfiltered);
		free_processes(filtered, nfiltered);
	}
	free_profiles(profiles, nprofiles);
	free_processes(processes, nprocesses);
	return ret;
}


static int compare_processes_by_profile(const void *a, const void *b) {
	return strcmp(((struct process *)a)->profile,
		      ((struct process *)b)->profile);
}

static int compare_processes_by_executable(const void *a, const void *b) {
	return strcmp(((struct process *)a)->exe,
		      ((struct process *)b)->exe);
}

/**
 * detailed_out - output a detailed listing of apparmor status
 * @outf: output file
 * @json: whether output should be in json format
 *
 * Return: 0 on success, else shell error
 */
static int detailed_output(FILE *outf, bool json) {
	size_t nprofiles = 0, nprocesses = 0;
	struct profile *profiles = NULL;
	struct process *processes = NULL;
	const char *profile_statuses[] = {"enforce", "complain", "kill", "unconfined"};
	const char *process_statuses[] = {"enforce", "complain", "unconfined", "mixed", "kill"};
	int ret;
	size_t i;

	ret = get_profiles(&profiles, &nprofiles);
	if (ret != 0) {
		goto exit;
	}
	ret = get_processes(profiles, nprofiles, &processes, &nprocesses);
	if (ret != 0) {
		dfprintf(stderr, "Failed to get processes: %d....\n", ret);
		goto exit;
	}

	if (json) {
		fprintf(outf, "{\"version\": \"%s\", \"profiles\": {", aa_status_json_version);
	} else {
		dfprintf(outf, "%zd profiles are loaded.\n", nprofiles);
	}

	for (i = 0; i < ARRAY_SIZE(profile_statuses); i++) {
		size_t nfiltered = 0, j;
		struct profile *filtered = NULL;
		ret = filter_profiles(profiles, nprofiles, profile_statuses[i], &filtered, &nfiltered);
		if (ret != 0) {
			goto exit;
		}
		if (!json) {
			dfprintf(outf, "%zd profiles are in %s mode.\n", nfiltered, profile_statuses[i]);
		}

		for (j = 0; j < nfiltered; j++) {
			if (json) {
				fprintf(outf, "%s\"%s\": \"%s\"",
				       i == 0 && j == 0 ? "" : ", ", filtered[j].name, profile_statuses[i]);
			} else {
				dfprintf(outf, "   %s\n", filtered[j].name);
			}
		}

		free_profiles(filtered, nfiltered);
	}
	if (json) {
		fprintf(outf, "}, \"processes\": {");
	} else {
		dfprintf(outf, "%zd processes have profiles defined.\n", nprocesses);
	}

	for (i = 0; i < ARRAY_SIZE(process_statuses); i++) {
		size_t nfiltered = 0, j;
		struct process *filtered = NULL;
		ret = filter_processes(processes, nprocesses, process_statuses[i], &filtered, &nfiltered);
		if (ret != 0) {
			goto exit;
		}
		if (!json) {
			if (strcmp(process_statuses[i], "unconfined") == 0) {
				dfprintf(outf, "%zd processes are unconfined but have a profile defined.\n", nfiltered);
			} else {
				dfprintf(outf, "%zd processes are in %s mode.\n", nfiltered, process_statuses[i]);
			}
		}

		if (!json) {
			qsort(filtered, nfiltered, sizeof(*filtered), compare_processes_by_profile);
			for (j = 0; j < nfiltered; j++) {
				dfprintf(outf, "   %s (%s) %s\n", filtered[j].exe, filtered[j].pid,
					// hide profile name if matches executable
					(strcmp(filtered[j].profile, filtered[j].exe) == 0 ?
					 "" :
					 filtered[j].profile));
			}
		} else {
			// json output requires processes to be grouped per executable
			qsort(filtered, nfiltered, sizeof(*filtered), compare_processes_by_executable);
			for (j = 0; j < nfiltered; j++) {
				if (j > 0 && strcmp(filtered[j].exe, filtered[j - 1].exe) == 0) {
					// same executable
					fprintf(outf, ", {\"profile\": \"%s\", \"pid\": \"%s\", \"status\": \"%s\"}",
					       filtered[j].profile, filtered[j].pid, filtered[j].mode);
				} else {
					fprintf(outf, "%s\"%s\": [{\"profile\": \"%s\", \"pid\": \"%s\", \"status\": \"%s\"}",
					       // first element will be a unique executable
					       j == 0 ? "" : "], ",
					       filtered[j].exe, filtered[j].profile, filtered[j].pid, filtered[j].mode);
				}

			}
			if (j > 0) {
				fprintf(outf, "]");
			}
		}
		free_processes(filtered, nfiltered);
	}
	if (json) {
		fprintf(outf, "}}\n");
	}

exit:
	free_processes(processes, nprocesses);
	free_profiles(profiles, nprofiles);
	return ret == 0 ? (nprofiles > 0 ? AA_EXIT_ENABLED : AA_EXIT_NO_POLICY) : ret;
}

/**
 * cmd_pretty_json - output nicelye formatted json to stdout
 * @command: command name - currently unused
 *
 * Return: 0 on success, shell error on failure
 */
static int cmd_pretty_json(FILE *outf)
{
	autofree char *buffer = NULL;
	autofree char *pretty = NULL;
	cJSON *json;
	FILE *f;	/* no autofclose - want explicit close to sync */
	size_t size;
	int ret;

	f = open_memstream(&buffer, &size);
	if (!f) {
		dfprintf(stderr, "Failed to open memstream: %m\n");
		return AA_EXIT_INTERNAL_ERROR;
	}

	ret = detailed_output(f, true);
	fclose(f);
	if (ret)
		return ret;

	json = cJSON_Parse(buffer);
	if (!json) {
		dfprintf(stderr, "Failed to parse json output");
		return AA_EXIT_INTERNAL_ERROR;
	}

	pretty = cJSON_Print(json);
	if (!pretty) {
		dfprintf(stderr, "Failed to print pretty json");
		return AA_EXIT_INTERNAL_ERROR;
	}
	fprintf(outf, "%s\n", pretty);

	return AA_EXIT_ENABLED;
}

static int print_usage(const char *command, bool error)
{
	int status = EXIT_SUCCESS;

	if (error) {
		status = EXIT_FAILURE;
	}

	printf("Usage: %s [OPTIONS]\n"
	 "Displays various information about the currently loaded AppArmor policy.\n"
	 "OPTIONS (one only):\n"
	 "  --enabled       returns error code if AppArmor not enabled\n"
	 "  --profiled      prints the number of loaded policies\n"
	 "  --enforced      prints the number of loaded enforcing policies\n"
	 "  --complaining   prints the number of loaded non-enforcing policies\n"
	 "  --kill          prints the number of loaded enforcing policies that kill tasks on policy violations\n"
	 "  --special-unconfined   prints the number of loaded non-enforcing policies in the special unconfined mode\n"
	 "  --process-mixed prints the number processes with mixed profile modes\n"
	 "  --json          displays multiple data points in machine-readable JSON format\n"
	 "  --pretty-json   same data as --json, formatted for human consumption as well\n"
	 "  --verbose       (default) displays multiple data points about loaded policy set\n"
	 "  --help          this message\n",
	 command);

	exit(status);

	return 0;
}


#define ARG_ENABLED	129
#define ARG_PROFILED	130
#define ARG_ENFORCED	131
#define ARG_COMPLAIN	132
#define ARG_KILL	133
#define ARG_UNCONFINED	134
#define ARG_PS_MIXED	135
#define ARG_JSON	136
#define ARG_PRETTY	137
#define ARG_VERBOSE 'v'
#define ARG_HELP 'h'

static char **parse_args(int argc, char **argv)
{
	int opt;
	struct option long_opts[] = {
		{"enabled", no_argument, 0, ARG_ENABLED},
		{"profiled", no_argument, 0, ARG_PROFILED},
		{"enforced", no_argument, 0, ARG_ENFORCED},
		{"complaining", no_argument, 0, ARG_COMPLAIN},
		{"kill", no_argument, 0, ARG_KILL},
		{"special-unconfined", no_argument, 0, ARG_UNCONFINED},
		{"process-mixed", no_argument, 0, ARG_PS_MIXED},
		{"json", no_argument, 0, ARG_JSON},
		{"pretty-json", no_argument, 0, ARG_PRETTY},
		{"verbose", no_argument, 0, ARG_VERBOSE},
		{"help", no_argument, 0, ARG_HELP},
		{NULL, 0, 0, 0},
	};

	// Using exit here is temporary
	while ((opt = getopt_long(argc, argv, "+vh", long_opts, NULL)) != -1) {
		switch (opt) {
		case ARG_ENABLED:
			exit(aa_is_enabled() == 1 ? 0 : AA_EXIT_DISABLED);
			break;
		case ARG_VERBOSE:
			verbose = 1;
			exit(detailed_output(stdout, false));
			break;
		case ARG_HELP:
			print_usage(argv[0], false);
			break;
		case ARG_PROFILED:
			exit(simple_filtered_count(stdout, NULL));
			break;
		case ARG_ENFORCED:
			exit(simple_filtered_count(stdout, "enforce"));
			break;
		case ARG_COMPLAIN:
			exit(simple_filtered_count(stdout, "complain"));
			break;
		case ARG_UNCONFINED:
			exit(simple_filtered_count(stdout, "unconfined"));
			break;
		case ARG_KILL:
			exit(simple_filtered_count(stdout, "kill"));
			break;
		case ARG_PS_MIXED:
			exit(simple_filtered_process_count(stdout, "mixed"));
			break;
		case ARG_JSON:
			exit(detailed_output(stdout, true));
			break;
		case ARG_PRETTY:
			exit(cmd_pretty_json(stdout));
			break;
		default:
			dfprintf(stderr, "Error: Invalid command.\n");
			print_usage(argv[0], true);
			break;
		}
	}

	return argv + optind;

}

int main(int argc, char **argv)
{
	int ret = EXIT_SUCCESS;
	const char *progname = argv[0];

	if (argc > 2) {
		dfprintf(stderr, "Error: Too many options.\n");
		print_usage(progname, true);
	} else if (argc == 2) {
		argv = parse_args(argc, argv);
		// temporary if we get here its an error
		ret = EXIT_FAILURE;
	} else {
		verbose = 1;
		ret = detailed_output(stdout, false);
	}

	exit(ret);
}
