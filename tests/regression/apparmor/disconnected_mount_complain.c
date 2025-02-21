#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sched.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>

#ifdef DEBUG
#include <sys/apparmor.h>
#endif

/*static int mount_setattr(int dirfd, const char *pathname, unsigned int flags,
        struct mount_attr *attr, size_t size) {
    return syscall(SYS_mount_setattr, dirfd, pathname, flags, attr, size);
}
static int open_tree(int dirfd, const char *filename, unsigned int flags) {
    return syscall(SYS_open_tree, dirfd, filename, flags);
}
static int move_mount(int from_dirfd, const char *from_pathname,
        int to_dirfd, const char *to_pathname, unsigned int flags) {
    return syscall(SYS_move_mount, from_dirfd, from_pathname, to_dirfd, to_pathname, flags);
}*/

#ifdef DEBUG
#define DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
#define DEBUG_PRINTF(...)
#endif

off_t file_size(int file_fd) {
    struct stat file_fd_stat;
    if (fstat(file_fd, &file_fd_stat) == -1) {
        // Immediate return to preserve errno
        return -1;
    } else {
        return file_fd_stat.st_size;
    }
}

int fork_and_execvat(int exec_fd, char* const* argv) {
    DEBUG_PRINTF("fork()ing to exec child binary\n");
    int pid = fork();
    if (pid == 0) {
        fexecve(exec_fd, argv, environ);
        perror("FAIL: Could not execveat binary");
        close(exec_fd);
        // Special exit that does not trigger any atexit handlers
        _exit(1);
    } else if (pid == -1) {
        perror("FAIL: Could not fork()");
        return -1;
    } else {
        DEBUG_PRINTF("Waiting on child\n");
        int child_status;
        wait(&child_status);
        if (!WIFEXITED(child_status)) {
            fprintf(stderr, "FAIL: child did not exit normally\n");
        }
        return WEXITSTATUS(child_status);
    }
}

int test_with_old_style_mount() {
    // Set up directory fds for future reference
    DEBUG_PRINTF("Opening fds for shadowed and shadowing directories\n");
    int shadowed_dirfd = openat(AT_FDCWD, "shadowed", O_DIRECTORY | O_PATH);
    if (shadowed_dirfd == -1) {
        perror("FAIL: could not open shadowed dirfd");
        return 1;
    }
    int shadowing_dirfd = openat(AT_FDCWD, "shadowing", O_DIRECTORY | O_PATH);
    if (shadowing_dirfd == -1) {
        perror("FAIL: could not open shadowing dirfd");
        close(shadowed_dirfd);
        return 1;
    }

    DEBUG_PRINTF("Opening fds for files in shadowed dir\n");
    int shadowed_file_fd = openat(shadowed_dirfd, "write_file", O_CREAT | O_RDWR, 0644);
    if (shadowed_file_fd == -1) {
        perror("FAIL: could not create file in shadowed dir");
        close(shadowed_dirfd);
        close(shadowing_dirfd);
        return 1;
    }
    int shadowed_exec_fd = openat(shadowed_dirfd, "true", O_PATH);
    if (shadowed_exec_fd == -1) {
        perror("FAIL: could not open executable file in shadowed dir");
        close(shadowed_file_fd);
        close(shadowing_dirfd);
        return 1;
    }

    DEBUG_PRINTF("Write something to file\n");
    int rc = 0;
    // Write something into the file
    if (write(shadowed_file_fd, "first\n", 6) == -1) {
        perror("FAIL: could not write to file before mount");
        rc |= 1;
        goto cleanup_fds;
    }

    DEBUG_PRINTF("Unshare mount ns and bind mount over shadowed dir\n");
    // Call unshare() to step into a new mount namespace
    if (unshare(CLONE_NEWNS) == -1) {
        perror("FAIL: could not unshare mount namespace");
        rc |= 1;
        goto cleanup_fds;
    }
    // Mount over directory, shadowing the path corresponding to the fd
    if (mount("shadowing", "shadowed", NULL, MS_BIND, NULL) == -1) {
        perror("FAIL: could not bind mount shadowing over shadowed\n");
        rc |= 1;
        goto cleanup_fds;
    }

    DEBUG_PRINTF("Write something to (now disconnected) file\n");
    // Write something into the file, again (after mount)
    if (write(shadowed_file_fd, "second\n", 7) == -1) {
        perror("FAIL: could not write to file after mount");
        rc |= 1;
        goto cleanup_mount;
    }

    // Now attempt to stat and read from the fd
    DEBUG_PRINTF("Stat disconnected file\n");
    if (lseek(shadowed_file_fd, 0, SEEK_SET) == -1) {
        perror("FAIL: could not lseek to start of file");
        rc |= 1;
        goto cleanup_mount;
    }
    off_t shadowed_file_size = file_size(shadowed_file_fd);
    if (shadowed_file_size == -1) {
        perror("FAIL: could not fstat file");
        rc |= 1;
        goto cleanup_mount;
    } else {
        DEBUG_PRINTF("File size is %ld\n", shadowed_file_size);
    }

    DEBUG_PRINTF("Read from disconnected file\n");
    char *file_contents_buf = calloc(shadowed_file_size+1, sizeof(char));
    if (read(shadowed_file_fd, file_contents_buf, shadowed_file_size) == -1) {
        perror("FAIL: could not read from file after mount");
        rc |= 1;
    } else {
        DEBUG_PRINTF("Read file contents:\n%s\n", file_contents_buf);
    }
    free(file_contents_buf);
    file_contents_buf = NULL;

    if (rc != 0) {
        goto cleanup_mount;
    }

    DEBUG_PRINTF("execvat disconnected binary file\n");
    char* const new_argv[] = {"true", NULL};
    if (fork_and_execvat(shadowed_exec_fd, new_argv) != 0) {
        perror("FAIL: child exited with non-zero status code");
        rc |= 1;
        goto cleanup_mount;
    }

    cleanup_mount:
    if (umount("shadowed") == -1) {
        perror("FAIL: could not unmount bind mount");
        rc |= 1;
    }
    cleanup_fds:
    close(shadowed_file_fd);
    close(shadowing_dirfd);
    close(shadowed_exec_fd);

    if (rc == 0) {
        fprintf(stderr, "PASS\n");
    }
    return rc;
}

int test_with_new_style_mount() {
    DEBUG_PRINTF("Unshare mount ns\n");
    // Call unshare() to step into a new mount namespace
    if (unshare(CLONE_NEWNS) == -1) {
        perror("FAIL: could not unshare mount namespace");
        return 1;
    }
    DEBUG_PRINTF("bind mount shadowed using new mount API\n");
    int fd_bind_mnt = open_tree(AT_FDCWD, "shadowed", OPEN_TREE_CLONE);
    if (fd_bind_mnt == -1) {
        perror("FAIL: could not open_tree bind mount to shadowed");
        return 1;
    }

    int rc = 0;

    DEBUG_PRINTF("bind mount nested preparation and attachment\n");
    int fd_inception_bind_mnt = open_tree(AT_FDCWD, "shadowing", OPEN_TREE_CLONE);
    if (fd_inception_bind_mnt == -1) {
        perror("FAIL: could not open_tree bind mount to be nested");
        close(fd_bind_mnt);
        return 1;
    }

    int move_status = move_mount(fd_inception_bind_mnt, "", fd_bind_mnt, "inner_dir", MOVE_MOUNT_F_EMPTY_PATH);
    /*
     * In the (6.11) kernel, move_mount has the following sequence of checks:
     * - Capability check for doing mounts at all (EPERM)
     * - Sanity checks for the flags (EINVAL)
     * - Verification that unmount wouldn't be required for the pathname
     * - LSM hook invocation for the syscall via security_move_mount
     *   - AppArmor: profile rule based denials (EACCES, EPERM), with some
     *     EINVALs that would trigger on external kernel changes that would
     *     require corresponding changes to the AppArmor kernel side
     * - do_move_mount(), which does some further sanity checks, such as
     *   - checking that the mountpoint is in our namespace (EINVAL)
     *   - checking that the old path is mounted (EINVAL)
     *   - checking that the new mount location would not create a loop (ELOOP)
     * 
     * The operation below should trigger EINVAL from do_move_mount due to
     * either the mountpoint not in the namespace (if fd_bind_mount was
     * set up with OPEN_TREE_CLONE) or the old path not being mounted (if not).
     *
     * TODO: disambiguating EINVALs from AppArmor vs outside of it would require
     * audit log inspection
     */
    if (move_status == -1 && errno != EINVAL) {
        // TODO: fails due to invalid arg
        perror("FAIL: could not attach nested bind mount");
        rc |= 1;
        goto cleanup_mount;
    }

    DEBUG_PRINTF("open file in not-actually-nested bind mount\n");
    int inception_fd = openat(fd_inception_bind_mnt, "cornh", O_RDONLY);
    if (inception_fd == -1) {
        perror("FAIL: could not open file in not-actually-nested bind mount");
        rc |= 1;
        goto cleanup_mount;
    }
    // Can close the fd now, as we only wanted to check successful open
    close(inception_fd);

    DEBUG_PRINTF("open executable file in bind mount\n");
    int shadowed_exec_fd = openat(fd_bind_mnt, "true", O_PATH);
    if (shadowed_exec_fd == -1) {
        perror("FAIL: could not open executable file in bind mount");
        rc |= 1;
        goto cleanup_file_fd;
    }

    DEBUG_PRINTF("execvat bind mount binary file\n");
    char* const new_argv[] = {"true", NULL};
    if (fork_and_execvat(shadowed_exec_fd, new_argv) != 0) {
        perror("FAIL: child exited with non-zero status code");
        rc |= 1;
        goto cleanup_file_fd;
    }

    cleanup_file_fd:
    close(shadowed_exec_fd);
    cleanup_mount:
    close(fd_inception_bind_mnt);
    close(fd_bind_mnt);

    if (rc == 0) {
        fprintf(stderr, "PASS\n");
    }
    return rc;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "FAIL: Usage: disconnected_mount_complain [WORKDIR] (old|new)");
        return 1;
    }
    #ifdef DEBUG
    {
        char *label;
        char *mode;
        if (aa_getcon(&label, &mode) == -1) {
            perror("FAIL: could not get current AppArmor confinement");
        } else {
            DEBUG_PRINTF("AppArmor confinement label=%s mode=%s\n", label, mode);
            free(label);
            label = NULL;
            mode = NULL;
        }
    }
    #endif
    if (chdir(argv[1]) != 0) {
        perror("FAIL: could not chdir to workdir");
        return 1;
    }
    if (strcmp(argv[2], "old") == 0) {
        return test_with_old_style_mount();
    } else if (strcmp(argv[2], "new") == 0) {
        return test_with_new_style_mount();
    } else {
        fprintf(stderr, "FAIL: second argument must be 'old' or 'new'\n");
        return 1;
    }
}
