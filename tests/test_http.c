/* test_http.c — tests unitaires de l'analyse HTTP et de la sécurisation des chemins. */
#include "http.h"

#include <stdio.h>
#include <string.h>

static int failures = 0, total = 0;
#define CHECK(cond) do { total++; if (!(cond)) { failures++; printf("ÉCHEC %s:%d : %s\n", __FILE__, __LINE__, #cond); } } while (0)

static parse_result parse(const char *raw, http_request *r) { return http_parse_request(raw, strlen(raw), r); }

static void test_parse(void) {
    http_request r;
    CHECK(parse("GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n", &r) == PARSE_OK);
    CHECK(r.method == METHOD_GET && strcmp(r.target, "/index.html") == 0);
    CHECK(parse("HEAD / HTTP/1.0\r\n\r\n", &r) == PARSE_OK && r.method == METHOD_HEAD);
    CHECK(parse("POST /x HTTP/1.1\r\n\r\n", &r) == PARSE_OK && r.method == METHOD_OTHER);
    CHECK(parse("GET /a?b=c#d HTTP/1.1\r\n\r\n", &r) == PARSE_OK && strcmp(r.target, "/a") == 0);
    /* Cas d'échec */
    CHECK(parse("GET /index.html HTTP/1.1\r\nHost: x\r\n", &r) == PARSE_INCOMPLETE);
    CHECK(parse("GET index.html HTTP/1.1\r\n\r\n", &r) == PARSE_BAD_REQUEST);
    CHECK(parse("GET /x HTTP/2.0\r\n\r\n", &r) == PARSE_BAD_VERSION);
    CHECK(parse("GET  HTTP/1.1\r\n\r\n", &r) == PARSE_BAD_REQUEST);
    CHECK(parse("GARBAGE\r\n\r\n", &r) == PARSE_BAD_REQUEST);
    char big[PHARE_MAX_PATH + 64];
    memset(big, 'a', sizeof big);
    memcpy(big, "GET /", 5);
    strcpy(big + sizeof big - 16, " HTTP/1.1\r\n\r\n");
    CHECK(parse(big, &r) == PARSE_URI_TOO_LONG);
}

static void test_url_decode(void) {
    char out[64];
    CHECK(url_decode("/caf%C3%A9%20bar", out, sizeof out) == 0 && strcmp(out, "/caf\xC3\xA9 bar") == 0);
    CHECK(url_decode("/a%2", out, sizeof out) == -1);       /* encodage tronqué */
    CHECK(url_decode("/a%zz", out, sizeof out) == -1);      /* hexadécimal invalide */
    CHECK(url_decode("/a%00.html", out, sizeof out) == -1); /* octet nul */
}

static void test_sanitize(void) {
    char out[256];
    CHECK(sanitize_path("/", out, sizeof out) == 0 && out[0] == '\0');
    CHECK(sanitize_path("/docs/./guide.html", out, sizeof out) == 0 && strcmp(out, "docs/guide.html") == 0);
    CHECK(sanitize_path("//a///b", out, sizeof out) == 0 && strcmp(out, "a/b") == 0);
    /* Attaques par remontée de dossiers et variantes encodées */
    CHECK(sanitize_path("/../etc/passwd", out, sizeof out) == -1);
    CHECK(sanitize_path("/a/../../secret", out, sizeof out) == -1);
    CHECK(sanitize_path("/%2e%2e/secret", out, sizeof out) == -1);
    CHECK(sanitize_path("/%2E%2E%2Fsecret", out, sizeof out) == -1);
    CHECK(sanitize_path("/..%5c..%5cwindows", out, sizeof out) == -1);  /* antislash encodé */
    CHECK(sanitize_path("/C:/Windows", out, sizeof out) == -1);          /* lecteur Windows */
    CHECK(sanitize_path("/a%0Ab", out, sizeof out) == -1);               /* caractère de contrôle */
    CHECK(sanitize_path("/...", out, sizeof out) == 0);                  /* nom de fichier légitime */
}

static void test_mime_and_escape(void) {
    CHECK(strncmp(mime_type("index.HTML"), "text/html", 9) == 0);
    CHECK(strcmp(mime_type("photo.jpeg"), "image/jpeg") == 0);
    CHECK(strcmp(mime_type("archive"), "application/octet-stream") == 0);
    CHECK(strcmp(mime_type("dossier.v2/fichier"), "application/octet-stream") == 0);
    char out[128];
    html_escape("<script>alert('x')</script>&", out, sizeof out);
    CHECK(strcmp(out, "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;") == 0);
    char tiny[6];
    html_escape("<<<<", tiny, sizeof tiny);   /* tampon trop petit : tronqué proprement, jamais débordé */
    CHECK(strcmp(tiny, "&lt;") == 0);
}

int main(void) {
    test_parse();
    test_url_decode();
    test_sanitize();
    test_mime_and_escape();
    printf("%d/%d tests réussis\n", total - failures, total);
    return failures ? 1 : 0;
}
