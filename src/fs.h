/* fs.h — accès fichiers portable Windows / POSIX. */
#ifndef PHARE_FS_H
#define PHARE_FS_H

#include <stddef.h>

typedef struct { int exists, is_dir; long long size; } fs_info;

int  fs_stat(const char *path, fs_info *info);

/* Vérifie que `path`, une fois résolu (liens symboliques compris), reste sous `root_real`.
 * Bloque un lien symbolique placé dans le dossier servi qui pointerait vers /etc par exemple. */
int  fs_within_root(const char *root_real, const char *path);

/* Résout le chemin absolu canonique du dossier racine. */
int  fs_realpath(const char *path, char *out, size_t out_size);

/* Appelle `cb` pour chaque entrée du dossier (hors "." et ".."). Renvoie le nombre d'entrées, -1 si erreur. */
typedef void (*fs_entry_cb)(const char *name, int is_dir, void *ctx);
int  fs_list(const char *dir, fs_entry_cb cb, void *ctx);

#endif
