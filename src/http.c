/* http.c — analyse HTTP et sécurisation des chemins (voir http.h). */
#include "http.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static const char *find_crlf(const char *buf, size_t len) {
    for (size_t i = 0; i + 1 < len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n') return buf + i;
    return NULL;
}

static int headers_complete(const char *buf, size_t len) {
    for (size_t i = 0; i + 3 < len; i++)
        if (memcmp(buf + i, "\r\n\r\n", 4) == 0) return 1;
    return 0;
}

parse_result http_parse_request(const char *buf, size_t len, http_request *out) {
    memset(out, 0, sizeof *out);
    const char *eol = find_crlf(buf, len);
    if (!eol) return len >= PHARE_MAX_REQUEST ? PARSE_URI_TOO_LONG : PARSE_INCOMPLETE;
    if (!headers_complete(buf, len)) return len >= PHARE_MAX_REQUEST ? PARSE_BAD_REQUEST : PARSE_INCOMPLETE;

    size_t line_len = (size_t)(eol - buf);
    const char *sp1 = memchr(buf, ' ', line_len);
    if (!sp1 || sp1 == buf) return PARSE_BAD_REQUEST;
    const char *sp2 = memchr(sp1 + 1, ' ', line_len - (size_t)(sp1 + 1 - buf));
    if (!sp2 || sp2 == sp1 + 1) return PARSE_BAD_REQUEST;

    size_t mlen = (size_t)(sp1 - buf);
    if (mlen == 3 && memcmp(buf, "GET", 3) == 0) out->method = METHOD_GET;
    else if (mlen == 4 && memcmp(buf, "HEAD", 4) == 0) out->method = METHOD_HEAD;
    else out->method = METHOD_OTHER;

    const char *version = sp2 + 1;
    size_t vlen = (size_t)(eol - version);
    if (vlen != 8 || (memcmp(version, "HTTP/1.1", 8) != 0 && memcmp(version, "HTTP/1.0", 8) != 0))
        return PARSE_BAD_VERSION;

    const char *target = sp1 + 1;
    size_t tlen = (size_t)(sp2 - target);
    const char *q = memchr(target, '?', tlen);       /* on ignore la chaîne de requête */
    if (q) tlen = (size_t)(q - target);
    const char *h = memchr(target, '#', tlen);
    if (h) tlen = (size_t)(h - target);
    if (tlen == 0 || target[0] != '/') return PARSE_BAD_REQUEST;
    if (tlen >= sizeof out->target) return PARSE_URI_TOO_LONG;
    memcpy(out->target, target, tlen);
    out->target[tlen] = '\0';
    return PARSE_OK;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    c = (char)tolower((unsigned char)c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int url_decode(const char *in, char *out, size_t out_size) {
    size_t o = 0;
    for (size_t i = 0; in[i]; i++) {
        if (o + 1 >= out_size) return -1;
        unsigned char c = (unsigned char)in[i];
        if (c == '%') {
            int hi = hexval(in[i + 1]), lo = hi < 0 ? -1 : hexval(in[i + 2]);
            if (hi < 0 || lo < 0) return -1;
            c = (unsigned char)(hi * 16 + lo);
            i += 2;
        }
        if (c == '\0') return -1;                      /* %00 : injection d'octet nul */
        out[o++] = (char)c;
    }
    out[o] = '\0';
    return 0;
}

int sanitize_path(const char *url_path, char *out, size_t out_size) {
    char decoded[PHARE_MAX_PATH];
    if (out_size == 0 || url_decode(url_path, decoded, sizeof decoded) != 0) return -1;

    size_t o = 0;
    out[0] = '\0';
    const char *p = decoded;
    while (*p) {
        while (*p == '/') p++;                         /* ignore les '/' multiples */
        if (!*p) break;
        const char *start = p;
        while (*p && *p != '/') {
            unsigned char c = (unsigned char)*p;
            if (c < 0x20 || c == 0x7f || c == '\\' || c == ':') return -1;
            p++;
        }
        size_t seg = (size_t)(p - start);
        if (seg == 1 && start[0] == '.') continue;    /* "." : segment neutre */
        if (seg == 2 && start[0] == '.' && start[1] == '.') return -1;   /* remontée interdite */
        if (o + seg + 2 > out_size) return -1;
        if (o > 0) out[o++] = '/';
        memcpy(out + o, start, seg);
        o += seg;
        out[o] = '\0';
    }
    return 0;
}

const char *mime_type(const char *path) {
    static const struct { const char *ext, *type; } table[] = {
        {".html", "text/html; charset=utf-8"}, {".htm", "text/html; charset=utf-8"},
        {".css", "text/css; charset=utf-8"},   {".js", "text/javascript; charset=utf-8"},
        {".json", "application/json"},         {".txt", "text/plain; charset=utf-8"},
        {".md", "text/markdown; charset=utf-8"}, {".svg", "image/svg+xml"},
        {".png", "image/png"}, {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"},
        {".gif", "image/gif"}, {".webp", "image/webp"}, {".ico", "image/x-icon"},
        {".pdf", "application/pdf"}, {".woff2", "font/woff2"}, {".mp4", "video/mp4"},
    };
    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, '/');
    if (dot && (!slash || dot > slash)) {
        for (size_t i = 0; i < sizeof table / sizeof table[0]; i++) {
            const char *a = dot, *b = table[i].ext;
            while (*a && *b && tolower((unsigned char)*a) == *b) { a++; b++; }
            if (!*a && !*b) return table[i].type;
        }
    }
    return "application/octet-stream";
}

size_t html_escape(const char *in, char *out, size_t out_size) {
    size_t o = 0;
    if (out_size == 0) return 0;
    for (; *in; in++) {
        const char *rep = NULL;
        switch (*in) {
            case '&': rep = "&amp;"; break;
            case '<': rep = "&lt;"; break;
            case '>': rep = "&gt;"; break;
            case '"': rep = "&quot;"; break;
            case '\'': rep = "&#39;"; break;
        }
        size_t n = rep ? strlen(rep) : 1;
        if (o + n + 1 > out_size) break;
        if (rep) memcpy(out + o, rep, n); else out[o] = *in;
        o += n;
    }
    out[o] = '\0';
    return o;
}

const char *status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 301: return "Moved Permanently";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 414: return "URI Too Long";
        case 500: return "Internal Server Error";
        case 505: return "HTTP Version Not Supported";
        default:  return "Unknown";
    }
}
