# Phare 🗼

Serveur HTTP de fichiers statiques écrit **en C**, sans aucune dépendance, qui tourne sous **Windows et Linux**.
Il sert le contenu d'un dossier à `http://127.0.0.1:8080/`, comme le fait `python -m http.server`, mais en natif.

```
> dist\phare.exe -d www
[2026-10-13 18:59:42] Phare sert D:/Dev/Applications/phare/www sur http://127.0.0.1:8080/
[2026-10-13 18:59:49] 127.0.0.1 -> 200
```

## Démarrage rapide

**Sans rien compiler (Windows)** : un exécutable prêt à l'emploi est fourni.

```
dist\phare.exe                  :: sert le dossier www sur http://127.0.0.1:8080/
dist\phare.exe -p 3000 -d C:\MonSite
```

**Compiler soi-même** : `build.bat` sous Windows (CMake ou gcc MSYS2), ou sous Linux :

```bash
cmake -S . -B build && cmake --build build
ctest --test-dir build        # tests unitaires
./build/phare -d www
```

| Option | Effet |
|---|---|
| `-p PORT` | port d'écoute (défaut 8080) |
| `-H ADRESSE` | adresse d'écoute (défaut `127.0.0.1`, donc invisible depuis le réseau ; `0.0.0.0` pour l'ouvrir) |
| `-d DOSSIER` | dossier servi (défaut `www`) |
| `--no-listing` | interdit l'affichage du contenu des dossiers sans `index.html` |

## Fonctionnalités

- Méthodes `GET` et `HEAD` (les autres renvoient `405` avec l'en-tête `Allow`).
- `index.html` servi automatiquement, sinon **listing du dossier** ; redirection `301` de `/dossier` vers `/dossier/`.
- Types MIME courants, envoi des gros fichiers par blocs de 16 Ko (mémoire constante).
- **Un thread par connexion** (`pthread` ou `_beginthreadex`), délai maximal de 10 s par client.
- Codes d'erreur précis : `400`, `403`, `404`, `405`, `414`, `505`, et journal horodaté.

## Sécurité : ce qui est bloqué, et comment

| Attaque | Protection |
|---|---|
| Remontée de dossiers `/../../etc/passwd` | Chaque segment est analysé ; `..` est refusé (`403`). |
| Variantes encodées `%2e%2e`, `%2F`, `%5c` | Décodage **avant** l'analyse des segments. |
| Lien symbolique vers l'extérieur du dossier | Le chemin résolu (`realpath`) doit rester sous la racine. |
| Octet nul `%00`, caractères de contrôle, `C:` | Refusés. |
| Nom de fichier piégé `<img onerror=…>` dans le listing | Noms échappés en HTML et encodés dans les liens. |
| Client lent qui monopolise un thread | `SO_RCVTIMEO` / `SO_SNDTIMEO` à 10 s. |
| Exposition involontaire sur le réseau | Écoute sur `127.0.0.1` par défaut. |
| Interprétation d'un fichier comme du HTML | En-tête `X-Content-Type-Options: nosniff`. |

## Architecture

```
src/http.c   analyse de la requête, décodage d'URL, sécurisation des chemins, types MIME
             → fonctions pures, testées sans réseau
src/fs.c     accès fichiers portable (stat, realpath, listing) : Windows / POSIX
src/main.c   sockets, threads, routage des réponses
tests/       32 tests unitaires, dont 11 sur les attaques de chemin
```

Le choix d'isoler toute la logique d'analyse dans `http.c`, sans entrée/sortie, permet de tester les cas
dangereux de façon exhaustive et rapide.

## Vérifications effectuées

- Compilation sans avertissement en `-Wall -Wextra -Wpedantic` (gcc) et en MinGW pour Windows.
- 32 tests unitaires réussis sous Linux **et** sous Windows.
- Tests de bout en bout : remontée de dossiers (brute, encodée, octet nul), lien symbolique vers `/etc`,
  nom de fichier piégé, `HTTP/2.0` refusé, requête malformée, 50 requêtes simultanées.

## Limites et pistes

- Une requête par connexion (`Connection: close`) : pas de *keep-alive*.
- Pas de HTTPS : à placer derrière un reverse proxy (Caddy, nginx) pour une mise en ligne.
- Sous Windows, les noms de fichiers non ASCII du listing passent par l'API ANSI.
- Pistes : *keep-alive*, requêtes partielles (`Range`) pour la vidéo, pool de threads, compression gzip.

---
Projet réalisé par **Thomas Balestro** — licence MIT.
