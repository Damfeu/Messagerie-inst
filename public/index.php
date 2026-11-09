<?php
declare(strict_types=1);
require __DIR__ . '/../src/bootstrap.php';
header('Cache-Control: no-store');
?>
<!doctype html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="referrer" content="no-referrer">
    <title>D-Send — messagerie chiffrée</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>

<!-- Connexion / inscription -->
<main id="view-auth" class="auth" hidden>
    <div class="auth-card">
        <div class="brand">D-Send</div>
        <p class="tagline">Messagerie et partage de fichiers chiffrés de bout en bout. Le serveur ne peut lire ni vos messages, ni vos fichiers.</p>

        <div class="tabs" role="tablist">
            <button type="button" role="tab" id="tab-login" aria-selected="true">Se connecter</button>
            <button type="button" role="tab" id="tab-register" aria-selected="false">Créer un compte</button>
        </div>

        <form id="form-auth" novalidate>
            <label for="auth-email">E-mail</label>
            <input type="email" id="auth-email" autocomplete="username" required maxlength="190">

            <label for="auth-password">Mot de passe</label>
            <input type="password" id="auth-password" autocomplete="current-password" required minlength="10" maxlength="200">

            <div id="confirm-wrap" hidden>
                <label for="auth-confirm">Confirmer le mot de passe</label>
                <input type="password" id="auth-confirm" autocomplete="new-password" minlength="10" maxlength="200">
                <p class="hint">10 caractères minimum. Ce mot de passe protège votre clé de chiffrement : s'il est perdu, vos messages ne peuvent pas être récupérés.</p>
            </div>

            <p class="alert" id="auth-error" role="alert" hidden></p>
            <button type="submit" class="primary" id="auth-submit">Se connecter</button>
            <p class="hint" id="auth-busy" hidden>Dérivation de la clé en cours…</p>
        </form>
    </div>
</main>

<!-- Déverrouillage après rechargement -->
<main id="view-unlock" class="auth" hidden>
    <div class="auth-card">
        <div class="brand">D-Send</div>
        <p class="tagline">Votre session est ouverte, mais la clé de chiffrement n'est plus en mémoire sur cet appareil. Saisissez votre mot de passe pour la déverrouiller.</p>
        <form id="form-unlock">
            <label for="unlock-password">Mot de passe</label>
            <input type="password" id="unlock-password" autocomplete="current-password" required>
            <p class="alert" id="unlock-error" role="alert" hidden></p>
            <button type="submit" class="primary">Déverrouiller</button>
            <button type="button" class="link" id="unlock-logout">Se déconnecter</button>
        </form>
    </div>
</main>

<!-- Application -->
<div id="view-app" class="app" hidden>
    <header class="topbar">
        <div class="brand">D-Send</div>
        <div class="me">
            <span class="lock" aria-hidden="true"></span>
            <span id="me-email"></span>
        </div>
        <div class="top-actions">
            <button type="button" class="danger" id="btn-panic" title="Efface les clés de cet appareil et ferme la session">Verrouillage d'urgence</button>
            <button type="button" class="ghost" id="btn-logout">Se déconnecter</button>
        </div>
    </header>

    <aside class="contacts" aria-label="Contacts">
        <h2>Discussions</h2>
        <ul id="contact-list"></ul>
        <p class="empty" id="contacts-empty" hidden>Aucun autre utilisateur pour l'instant. Créez un second compte dans une autre fenêtre pour tester.</p>
    </aside>

    <section class="thread" aria-label="Conversation">
        <div class="thread-empty" id="thread-empty">
            <p>Choisissez une discussion à gauche.</p>
            <p class="hint">Chaque message et chaque fichier est chiffré dans votre navigateur avant l'envoi.</p>
        </div>

        <div id="thread" hidden>
            <div class="thread-head">
                <div class="avatar" id="peer-avatar"></div>
                <div class="peer">
                    <div id="peer-email"></div>
                    <button type="button" class="link small" id="btn-safety">Vérifier le numéro de sécurité</button>
                </div>
                <button type="button" class="ghost small" id="btn-clear">Supprimer la discussion</button>
            </div>
            <div class="safety" id="safety" hidden>
                <p>Comparez ce numéro avec votre correspondant, de vive voix. S'il est identique des deux côtés, personne ne s'est interposé.</p>
                <code id="safety-number"></code>
            </div>
            <div class="messages" id="messages" aria-live="polite"></div>
            <form class="composer" id="composer">
                <label class="attach" for="file-input" title="Joindre un fichier (8 Mo max.)">Fichier</label>
                <input type="file" id="file-input" hidden>
                <label for="msg-input" class="sr-only">Message</label>
                <input type="text" id="msg-input" placeholder="Écrire un message chiffré…" autocomplete="off" maxlength="4000">
                <button type="submit" class="primary">Envoyer</button>
            </form>
            <p class="alert" id="send-error" role="alert" hidden></p>
        </div>
    </section>
</div>

<div class="toast" id="toast" role="status" hidden></div>

<script src="assets/crypto.js"></script>
<script src="assets/app.js"></script>
</body>
</html>
