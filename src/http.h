/* http.h — analyse des requêtes et sécurisation des chemins.
 * Fonctions pures, sans réseau ni système de fichiers : entièrement testables. */
#ifndef PHARE_HTTP_H
#define PHARE_HTTP_H

#include <stddef.h>

#define PHARE_MAX_REQUEST   8192
#define PHARE_MAX_PATH      1024

typedef enum { METHOD_GET, METHOD_HEAD, METHOD_OTHER } http_method;

typedef enum {
    PARSE_OK = 0,
    PARSE_INCOMPLETE,      /* en-têtes pas encore terminés */
    PARSE_BAD_REQUEST,     /* 400 */
    PARSE_URI_TOO_LONG,    /* 414 */
    PARSE_BAD_VERSION      /* 505 */
} parse_result;

typedef struct {
    http_method method;
    char target[PHARE_MAX_PATH];   /* chemin brut, sans la chaîne de requête */
} http_request;

/* Analyse la ligne de requête. `buf` n'a pas besoin d'être terminé par '\0'. */
parse_result http_parse_request(const char *buf, size_t len, http_request *out);

/* Décode les %XX d'une URL. Renvoie 0 si succès, -1 si encodage invalide ou octet nul. */
int url_decode(const char *in, char *out, size_t out_size);

/* Transforme un chemin d'URL en chemin relatif sûr (segments séparés par '/').
 * Refuse : "..", octets de contrôle, antislash, ':' (lecteur Windows), chemins trop longs.
 * Renvoie 0 si sûr, -1 sinon. Un résultat vide signifie la racine. */
int sanitize_path(const char *url_path, char *out, size_t out_size);

/* Type MIME selon l'extension du fichier. */
const char *mime_type(const char *path);

/* Échappe un texte pour l'insérer dans du HTML. Renvoie la longueur écrite. */
size_t html_escape(const char *in, char *out, size_t out_size);

/* Texte standard d'un code de statut. */
const char *status_text(int code);

#endif
