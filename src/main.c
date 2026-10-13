/* main.c — Phare : serveur HTTP de fichiers statiques, multi-thread, Windows et Linux.
 *
 * Usage : phare [-p PORT] [-H ADRESSE] [-d DOSSIER] [--no-listing]
 *   -p  port d'écoute (défaut 8080)
 *   -H  adresse d'écoute (défaut 127.0.0.1 : accessible uniquement depuis cette machine)
 *   -d  dossier servi (défaut ./www)
 */
#include "fs.h"
#include "http.h"

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0600   /* inet_pton / inet_ntop : Windows Vista et plus */
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <process.h>
   typedef SOCKET sock_t;
#  define CLOSESOCK closesocket
#  define BAD_SOCK INVALID_SOCKET
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <pthread.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <unistd.h>
   typedef int sock_t;
#  define CLOSESOCK close
#  define BAD_SOCK (-1)
#endif

#define CHUNK 16384

static char g_root[4096];          /* dossier servi, chemin canonique */
static int  g_listing = 1;

/* ── Journalisation thread-safe (un printf par ligne) ─────────── */
static void log_line(const char *fmt, ...) {
    char ts[32], msg[1200];
    time_t now = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    printf("[%s] %s\n", ts, msg);
    fflush(stdout);
}

/* ── Envoi ───────────────────────────────────────────────────── */
static int send_all(sock_t s, const char *buf, size_t len) {
    while (len > 0) {
        int n = send(s, buf, (int)(len > 65536 ? 65536 : len), 0);
        if (n <= 0) return -1;
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static void send_headers(sock_t s, int code, const char *type, long long length, const char *extra) {
    char head[1024];
    int n = snprintf(head, sizeof head,
        "HTTP/1.1 %d %s\r\n"
        "Server: Phare/1.0\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lld\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Connection: close\r\n"
        "%s\r\n",
        code, status_text(code), type, length, extra ? extra : "");
    if (n > 0) send_all(s, head, (size_t)n);
}

static void send_error(sock_t s, int code, int head_only) {
    char body[256];
    int n = snprintf(body, sizeof body,
        "<!doctype html><meta charset=utf-8><title>%d</title>"
        "<h1>%d %s</h1><p>Phare</p>\n", code, code, status_text(code));
    send_headers(s, code, "text/html; charset=utf-8", n, NULL);
    if (!head_only) send_all(s, body, (size_t)n);
}

/* ── Listing de dossier (noms échappés : pas d'injection HTML) ── */
typedef struct { char *buf; size_t len, cap; const char *base; } listing;

static void lst_append(listing *l, const char *s) {
    size_t n = strlen(s);
    if (l->len + n + 1 > l->cap) {
        size_t cap = (l->cap ? l->cap * 2 : 4096);
        while (cap < l->len + n + 1) cap *= 2;
        char *p = realloc(l->buf, cap);
        if (!p) return;
        l->buf = p;
        l->cap = cap;
    }
    memcpy(l->buf + l->len, s, n + 1);
    l->len += n;
}

static void url_encode_seg(const char *in, char *out, size_t size) {
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    for (; *in && o + 4 < size; in++) {
        unsigned char c = (unsigned char)*in;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strchr("-_.~", c)) out[o++] = (char)c;
        else { out[o++] = '%'; out[o++] = hex[c >> 4]; out[o++] = hex[c & 15]; }
    }
    out[o] = '\0';
}

static void lst_entry(const char *name, int is_dir, void *ctx) {
    listing *l = ctx;
    char esc[1024], enc[1024], line[2600];
    html_escape(name, esc, sizeof esc);
    url_encode_seg(name, enc, sizeof enc);
    snprintf(line, sizeof line, "<li><a href=\"%s%s\">%s%s</a></li>\n", enc, is_dir ? "/" : "", esc, is_dir ? "/" : "");
    lst_append(l, line);
}

static void send_listing(sock_t s, const char *fs_path, const char *url_path, int head_only) {
    listing l = {0};
    char esc[PHARE_MAX_PATH * 6];
    html_escape(url_path, esc, sizeof esc);
    lst_append(&l, "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width\">"
                   "<style>body{font:15px system-ui;max-width:720px;margin:40px auto;padding:0 16px}"
                   "a{text-decoration:none}li{padding:4px 0}</style><title>Index</title><h1>Index de ");
    lst_append(&l, esc);
    lst_append(&l, "</h1><ul>\n");
    if (strcmp(url_path, "/") != 0) lst_append(&l, "<li><a href=\"../\">../</a></li>\n");
    if (fs_list(fs_path, lst_entry, &l) < 0) { free(l.buf); send_error(s, 500, head_only); return; }
    lst_append(&l, "</ul>\n");
    if (!l.buf) { send_error(s, 500, head_only); return; }
    send_headers(s, 200, "text/html; charset=utf-8", (long long)l.len, NULL);
    if (!head_only) send_all(s, l.buf, l.len);
    free(l.buf);
}

/* ── Traitement d'une connexion ──────────────────────────────── */
static int serve_file(sock_t s, const char *path, long long size, int head_only) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    send_headers(s, 200, mime_type(path), size, NULL);
    if (!head_only) {
        char buf[CHUNK];
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, f)) > 0)
            if (send_all(s, buf, n) != 0) break;
    }
    fclose(f);
    return 0;
}

static int handle(sock_t s, const char *peer) {
    char buf[PHARE_MAX_REQUEST];
    size_t len = 0;
    http_request req;
    parse_result pr = PARSE_INCOMPLETE;

    while (pr == PARSE_INCOMPLETE && len < sizeof buf) {
        int n = recv(s, buf + len, (int)(sizeof buf - len), 0);
        if (n <= 0) return n == 0 ? 0 : 408;
        len += (size_t)n;
        pr = http_parse_request(buf, len, &req);
    }
    if (pr == PARSE_INCOMPLETE) pr = PARSE_BAD_REQUEST;
    int head_only = req.method == METHOD_HEAD;

    if (pr != PARSE_OK) {
        int code = pr == PARSE_URI_TOO_LONG ? 414 : pr == PARSE_BAD_VERSION ? 505 : 400;
        send_error(s, code, 0);
        return code;
    }
    if (req.method == METHOD_OTHER) {
        send_headers(s, 405, "text/plain; charset=utf-8", 0, "Allow: GET, HEAD\r\n");
        return 405;
    }

    char rel[PHARE_MAX_PATH], full[PHARE_MAX_PATH + 4200];
    if (sanitize_path(req.target, rel, sizeof rel) != 0) { send_error(s, 403, head_only); return 403; }
    snprintf(full, sizeof full, "%s%s%s", g_root, rel[0] ? "/" : "", rel);

    fs_info info;
    if (fs_stat(full, &info) != 0) { send_error(s, 404, head_only); return 404; }
    if (!fs_within_root(g_root, full)) { send_error(s, 403, head_only); return 403; }

    if (info.is_dir) {
        size_t tl = strlen(req.target);
        if (tl == 0 || req.target[tl - 1] != '/') {          /* /dossier -> /dossier/ */
            char loc[PHARE_MAX_PATH + 32];
            snprintf(loc, sizeof loc, "Location: %s/\r\n", req.target);
            send_headers(s, 301, "text/plain; charset=utf-8", 0, loc);
            return 301;
        }
        char index[sizeof full + 16];
        snprintf(index, sizeof index, "%s/index.html", full);
        fs_info ii;
        if (fs_stat(index, &ii) == 0 && !ii.is_dir) {
            if (serve_file(s, index, ii.size, head_only) == 0) return 200;
            send_error(s, 500, head_only);
            return 500;
        }
        if (!g_listing) { send_error(s, 403, head_only); return 403; }
        send_listing(s, full, req.target, head_only);
        return 200;
    }
    if (serve_file(s, full, info.size, head_only) != 0) { send_error(s, 403, head_only); return 403; }
    (void)peer;
    return 200;
}

typedef struct { sock_t s; char peer[64]; } conn;

#ifdef _WIN32
static unsigned __stdcall worker(void *arg)
#else
static void *worker(void *arg)
#endif
{
    conn *c = arg;
    /* Délai maximal : un client qui n'envoie rien ne bloque pas un thread indéfiniment */
#ifdef _WIN32
    DWORD tv = 10000;
#else
    struct timeval tv = {10, 0};
#endif
    setsockopt(c->s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    setsockopt(c->s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof tv);
    int code = handle(c->s, c->peer);
    if (code) log_line("%s -> %d", c->peer, code);
    CLOSESOCK(c->s);
    free(c);
    return 0;
}

static void usage(void) {
    fprintf(stderr, "Usage : phare [-p PORT] [-H ADRESSE] [-d DOSSIER] [--no-listing]\n");
}

int main(int argc, char **argv) {
    int port = 8080;
    const char *host = "127.0.0.1", *dir = "www";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-H") && i + 1 < argc) host = argv[++i];
        else if (!strcmp(argv[i], "-d") && i + 1 < argc) dir = argv[++i];
        else if (!strcmp(argv[i], "--no-listing")) g_listing = 0;
        else { usage(); return 1; }
    }
    if (port < 1 || port > 65535) { fprintf(stderr, "Port invalide.\n"); return 1; }
    if (fs_realpath(dir, g_root, sizeof g_root) != 0) { fprintf(stderr, "Dossier introuvable : %s\n", dir); return 1; }

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { fprintf(stderr, "WSAStartup a échoué.\n"); return 1; }
#else
    signal(SIGPIPE, SIG_IGN);    /* un client qui ferme brutalement ne doit pas tuer le serveur */
#endif

    sock_t srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == BAD_SOCK) { perror("socket"); return 1; }
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof yes);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) { fprintf(stderr, "Adresse invalide : %s\n", host); return 1; }
    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0) { fprintf(stderr, "Impossible d'écouter sur %s:%d (port déjà utilisé ?)\n", host, port); return 1; }
    if (listen(srv, 64) != 0) { perror("listen"); return 1; }

    log_line("Phare sert %s sur http://%s:%d/  (Ctrl+C pour arrêter)", g_root, host, port);

    for (;;) {
        struct sockaddr_in cli;
        socklen_t cl = sizeof cli;
        sock_t s = accept(srv, (struct sockaddr *)&cli, &cl);
        if (s == BAD_SOCK) continue;
        conn *c = malloc(sizeof *c);
        if (!c) { CLOSESOCK(s); continue; }
        c->s = s;
        inet_ntop(AF_INET, &cli.sin_addr, c->peer, sizeof c->peer);
#ifdef _WIN32
        HANDLE th = (HANDLE)_beginthreadex(NULL, 0, worker, c, 0, NULL);
        if (th) CloseHandle(th); else { CLOSESOCK(s); free(c); }
#else
        pthread_t th;
        if (pthread_create(&th, NULL, worker, c) == 0) pthread_detach(th);
        else { CLOSESOCK(s); free(c); }
#endif
    }
}
