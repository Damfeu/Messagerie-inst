# Sécurité de D-Send

## Modèle de chiffrement (v2)

| Élément | Mécanisme |
| --- | --- |
| Mot de passe | Ne quitte jamais le navigateur. PBKDF2-SHA-256, 600 000 itérations, sel aléatoire de 128 bits. |
| Authentification | Le navigateur dérive un secret d'authentification de 256 bits. Le serveur le hache en **Argon2id** (repli bcrypt). |
| Clé d'identité | Paire ECDH P-256 générée dans le navigateur. Clé privée chiffrée en AES-256-GCM par une clé dérivée du mot de passe, puis réimportée en « non exportable ». |
| Clé de conversation | ECDH entre les deux utilisateurs, puis HKDF-SHA-256. |
| Messages et fichiers | AES-256-GCM, IV aléatoire de 96 bits par message. Le nom et le type du fichier sont chiffrés avec son contenu. |
| Vérification | Numéro de sécurité de 60 chiffres (SHA-256 des deux clés publiques), à comparer de vive voix. |

**Ce que voit le serveur :** les adresses e-mail, qui écrit à qui et quand, la taille des messages. **Ce qu'il ne voit pas :** le mot de passe, les clés privées, le contenu des messages, les fichiers et leurs noms.

## Audit de la v1 (2024) et corrections

Audit réalisé en novembre 2026 sur la première version, en la faisant tourner et en l'attaquant.

| # | Faille v1 constatée | OWASP Top 10 2021 | Correction v2 |
| --- | --- | --- | --- |
| 1 | Session = cookie `id=<numéro>` : changer le numéro permettait de lire les messages de n'importe qui, sans mot de passe | A01 Contrôle d'accès, A07 Authentification | Session PHP serveur, cookie `HttpOnly` + `SameSite=Strict` + `Secure`, régénération à la connexion, expiration après 30 min d'inactivité |
| 2 | Messages stockés en clair dans la base | A02 Défaillances cryptographiques | Chiffrement de bout en bout dans le navigateur : la base ne contient que du chiffré |
| 3 | Mots de passe hachés en MD5 | A02 | Le mot de passe n'est plus envoyé ; le secret dérivé est haché en Argon2id |
| 4 | XSS stocké : un message contenant `<script>` s'exécutait chez le destinataire | A03 Injection | Affichage uniquement via `textContent`, jamais `innerHTML` ; Content-Security-Policy stricte sans script inline |
| 5 | Envoi de message par requête GET, sans protection CSRF | A01, A04 | Écritures en POST JSON avec jeton CSRF obligatoire |
| 6 | Aucune limite de tentatives de connexion | A07 | 5 échecs par 15 minutes ; clé de limitation = HMAC(e-mail + IP), rien n'est stocké en clair |
| 7 | Messages d'erreur révélant l'existence d'un compte | A07 | Message générique ; sel factice mais stable pour les comptes inexistants ; vérification à temps constant |
| 8 | Identifiants de base de données dans le code versionné | A05 Mauvaise configuration | `config/config.php` hors dépôt Git ; racine web limitée à `public/` |
| 9 | Aucun en-tête de sécurité | A05 | CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy |
| 10 | Bug : utilisateur non connecté après inscription | — | Corrigé |

## Tests effectués (v2)

- Parcours complet dans un navigateur automatisé (Playwright) : inscription de deux comptes, message texte, envoi d'une photo, réponse, numéro de sécurité identique des deux côtés.
- Base de données inspectée : aucun texte de message ni nom de fichier en clair.
- Cookie forgé `id=2` : refusé (401).
- Requête POST sans jeton CSRF : refusée (403).
- Message contenant `<script>` et `<img onerror>` : affiché comme du texte, aucun script exécuté.
- 6e tentative de connexion erronée : bloquée (429).
- Verrouillage d'urgence : la clé locale est effacée (IndexedDB vide).

## Limites connues et prochaines étapes

- La clé de conversation est statique entre deux personnes : pas de confidentialité persistante (*forward secrecy*). Étape suivante : un protocole à double cliquet (type Signal).
- Les métadonnées (qui parle à qui, quand) restent visibles du serveur.
- PBKDF2 est utilisé car il est natif dans Web Crypto ; Argon2id côté navigateur (via libsodium/WebAssembly) serait plus résistant.
- Le serveur distribue les clés publiques : la vérification du numéro de sécurité est ce qui protège contre une substitution de clé.
- Pas encore d'authentification à deux facteurs (WebAuthn / FIDO2 prévu).

Pour signaler une vulnérabilité : adododji7@gmail.com.
