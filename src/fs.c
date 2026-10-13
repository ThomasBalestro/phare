/* fs.c — implémentation portable de fs.h. */
#include "fs.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#  include <sys/stat.h>

int fs_stat(const char *path, fs_info *info) {
    struct _stat64 st;
    memset(info, 0, sizeof *info);
    if (_stat64(path, &st) != 0) return -1;
    info->exists = 1;
    info->is_dir = (st.st_mode & _S_IFDIR) != 0;
    info->size = (long long)st.st_size;
    return 0;
}

int fs_realpath(const char *path, char *out, size_t out_size) {
    DWORD n = GetFullPathNameA(path, (DWORD)out_size, out, NULL);
    if (n == 0 || n >= out_size) return -1;
    for (char *p = out; *p; p++) if (*p == '\\') *p = '/';
    size_t len = strlen(out);
    if (len > 1 && out[len - 1] == '/') out[len - 1] = '\0';
    return 0;
}

int fs_list(const char *dir, fs_entry_cb cb, void *ctx) {
    char pattern[MAX_PATH];
    if (snprintf(pattern, sizeof pattern, "%s/*", dir) >= (int)sizeof pattern) return -1;
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    int count = 0;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) continue;
        cb(fd.cFileName, (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0, ctx);
        count++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return count;
}
#else
#  include <dirent.h>
#  include <limits.h>
#  include <stdlib.h>
#  include <sys/stat.h>

int fs_stat(const char *path, fs_info *info) {
    struct stat st;
    memset(info, 0, sizeof *info);
    if (stat(path, &st) != 0) return -1;
    info->exists = 1;
    info->is_dir = S_ISDIR(st.st_mode);
    info->size = (long long)st.st_size;
    return 0;
}

int fs_realpath(const char *path, char *out, size_t out_size) {
    char buf[PATH_MAX];
    if (!realpath(path, buf) || strlen(buf) >= out_size) return -1;
    strcpy(out, buf);
    return 0;
}

int fs_list(const char *dir, fs_entry_cb cb, void *ctx) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    int count = 0;
    struct dirent *e;
    char full[PATH_MAX];
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;          /* fichiers cachés et . / .. */
        fs_info info;
        if (snprintf(full, sizeof full, "%s/%s", dir, e->d_name) >= (int)sizeof full) continue;
        if (fs_stat(full, &info) != 0) continue;
        cb(e->d_name, info.is_dir, ctx);
        count++;
    }
    closedir(d);
    return count;
}
#endif

int fs_within_root(const char *root_real, const char *path) {
    char resolved[4096];
    if (fs_realpath(path, resolved, sizeof resolved) != 0) return 0;
    size_t n = strlen(root_real);
#ifdef _WIN32
    int same = _strnicmp(resolved, root_real, n) == 0;   /* chemins insensibles à la casse sous Windows */
#else
    int same = strncmp(resolved, root_real, n) == 0;
#endif
    return same && (resolved[n] == '\0' || resolved[n] == '/');
}
