# D-Send

Messagerie instantanée et partage de fichiers **chiffrés de bout en bout**. Le serveur relaie et stocke les messages sans pouvoir les lire.

Projet d'ADODODJI Kokouvi Damaz. Une première version a été écrite en 2024 pendant ma formation ; en novembre 2026, je l'ai auditée et entièrement reconstruite autour de la sécurité. Le détail de l'audit, des failles trouvées et de leurs corrections est dans [SECURITY.md](SECURITY.md).

## Fonctionnalités

- Messages texte chiffrés dans le navigateur (AES-256-GCM)
- Envoi de fichiers chiffrés jusqu'à 8 Mo, avec aperçu des images
- Mot de passe jamais transmis au serveur
- Numéro de sécurité pour vérifier son correspondant
- Suppression d'une discussion sur le serveur
- Verrouillage d'urgence : efface les clés de l'appareil et ferme la session
- Interface utilisable sur téléphone, thème clair et sombre

## Technologies

PHP 8.1+ (sans framework), MySQL/MariaDB ou SQLite, JavaScript natif, Web Crypto API. Aucune dépendance externe ni CDN.

## Arborescence

```
index.php          redirige vers public/ (utile sous XAMPP)
public/            racine web (seul dossier exposé)
  index.php        interface
  api.php          API JSON
  assets/          crypto.js, app.js, style.css, polices
src/bootstrap.php  session, CSRF, en-têtes de sécurité, base de données
config/            config.example.php (à copier en config.php)
database/          schémas MySQL et SQLite
bin/init-db.php    création des tables
tests/             test de bout en bout (Playwright) et contrôles de sécurité
```

## Installation locale

```bash
cp config/config.example.php config/config.php   # SQLite par défaut
php bin/init-db.php
php -S localhost:8000 -t public
```

Ouvrez http://localhost:8000, créez deux comptes dans deux navigateurs (ou une fenêtre privée) et échangez des messages.

## Mise en production

1. Serveur avec PHP 8.1+ et MySQL ; **HTTPS obligatoire** (Web Crypto ne fonctionne qu'en contexte sécurisé).
2. Créer la base, puis renseigner `config/config.php` (DSN MySQL, identifiants, `app_secret` aléatoire).
3. `php bin/init-db.php`, et dans `php.ini` : `post_max_size = 20M` au minimum (un fichier de 8 Mo chiffré pèse environ 14 Mo à l'envoi).
4. Pointer la racine du site (DocumentRoot) sur le dossier `public/`. Sous XAMPP, ouvrez simplement http://localhost/<dossier>/ : la page redirige vers `public/` et les autres dossiers sont bloqués par leurs fichiers `.htaccess`.

## Tests

Les tests tournent sur une base séparée (`storage/test.sqlite`), jamais sur la vraie.

```bash
# 1. Serveur de test, base neuve (post_max_size relevé pour le fichier de 7,8 Mo)
rm -f storage/test.sqlite
DSEND_TEST_DB=test.sqlite php -d post_max_size=20M -S localhost:8000 -t public

# 2. Dans un autre terminal
npm install && npx playwright install chromium   # une seule fois
npm test
```

`npm test` lance `tests/securite.sh` (attaques côté serveur) puis `tests/e2e.js` (parcours complet dans Chromium). Pour viser une autre adresse : `BASE_URL=http://localhost:8080 npm test`.

Vercel n'exécute pas PHP avec une base MySQL : utilisez un VPS ou un hébergement PHP classique.
