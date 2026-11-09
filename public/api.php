<?php
declare(strict_types=1);

/*
 * D-Send v2 — API JSON.
 * Le serveur authentifie, autorise et relaie. Il ne déchiffre jamais rien :
 * il ne reçoit ni mot de passe, ni clé privée en clair, ni contenu de message lisible.
 */

require __DIR__ . '/../src/bootstrap.php';

$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

// Toute écriture passe par POST + jeton CSRF (l'ancienne version écrivait via GET).
if ($method === 'POST') {
    require_csrf();
} elseif ($method !== 'GET') {
    json_error('Méthode non autorisée.', 405);
}

$colors = ['blue', 'cyan', 'red', 'green', 'slate', 'pink', 'purple', 'orange'];

function require_auth(): int
{
    $uid = current_user_id();
    if ($uid === null) {
        json_error('Session expirée. Reconnectez-vous.', 401);
    }
    return $uid;
}

function user_row(int $id): ?array
{
    $st = db()->prepare('SELECT id, email, color, public_key, enc_private_key, private_key_iv, kdf_salt FROM users WHERE id = ?');
    $st->execute([$id]);
    return $st->fetch() ?: null;
}

function clean_email(mixed $v): string
{
    $email = is_string($v) ? strtolower(trim($v)) : '';
    if (strlen($email) > 190 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        json_error('Adresse e-mail invalide.');
    }
    return $email;
}

switch ("$method $action") {

    case 'GET session':
        $uid = current_user_id();
        json_out([
            'csrf' => csrf_token(),
            'user' => $uid ? user_row($uid) : null,
        ]);

    case 'POST prelogin':
        // Renvoie le sel de dérivation. Pour un e-mail inconnu, un sel factice mais stable
        // est renvoyé : on ne peut pas savoir si un compte existe (énumération).
        $in = json_input();
        $email = clean_email($in['email'] ?? '');
        $st = db()->prepare('SELECT kdf_salt FROM users WHERE email = ?');
        $st->execute([$email]);
        $salt = $st->fetchColumn();
        if (!$salt) {
            $salt = base64_encode(substr(hash_hmac('sha256', 'salt|' . $email, $CONFIG['app_secret'], true), 0, 16));
        }
        json_out(['salt' => $salt]);

    case 'POST register':
        $in = json_input();
        $email = clean_email($in['email'] ?? '');
        $authSecret = b64_field($in, 'auth_secret', 64);
        $salt = b64_field($in, 'kdf_salt', 32);
        $pub = b64_field($in, 'public_key', 400);
        $encPriv = b64_field($in, 'enc_private_key', 1000);
        $privIv = b64_field($in, 'private_key_iv', 24);

        $st = db()->prepare('SELECT 1 FROM users WHERE email = ?');
        $st->execute([$email]);
        if ($st->fetchColumn()) {
            json_error('Un compte existe déjà avec cette adresse.', 409);
        }
        db()->prepare('INSERT INTO users (email, auth_hash, kdf_salt, public_key, enc_private_key, private_key_iv, color, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
            ->execute([$email, password_hash($authSecret, password_algo()), $salt, $pub, $encPriv, $privIv, $colors[random_int(0, 7)], time()]);
        login_user((int) db()->lastInsertId());
        json_out(['user' => user_row(current_user_id()), 'csrf' => csrf_token()], 201);

    case 'POST login':
        $in = json_input();
        $email = clean_email($in['email'] ?? '');
        $authSecret = b64_field($in, 'auth_secret', 64);
        if (too_many_attempts($email)) {
            json_error('Trop de tentatives. Réessayez dans 15 minutes.', 429);
        }
        $st = db()->prepare('SELECT id, auth_hash FROM users WHERE email = ?');
        $st->execute([$email]);
        $row = $st->fetch();
        // Vérification même sans compte, pour un temps de réponse identique.
        $hash = $row['auth_hash'] ?? password_hash('leurre', password_algo());
        if (!password_verify($authSecret, $hash) || !$row) {
            record_failed_attempt($email);
            json_error('Adresse e-mail ou mot de passe incorrect.', 401);
        }
        clear_attempts($email);
        login_user((int) $row['id']);
        json_out(['user' => user_row((int) $row['id']), 'csrf' => csrf_token()]);

    case 'POST logout':
        logout_user();
        json_out(['ok' => true]);

    case 'GET contacts':
        $uid = require_auth();
        $st = db()->prepare(
            'SELECT u.id, u.email, u.color, u.public_key,
                    (SELECT MAX(m.created_at) FROM messages m
                      WHERE (m.sender_id = u.id AND m.receiver_id = :me) OR (m.sender_id = :me2 AND m.receiver_id = u.id)) AS last_at
               FROM users u WHERE u.id <> :me3 ORDER BY last_at DESC, u.email ASC'
        );
        $st->execute(['me' => $uid, 'me2' => $uid, 'me3' => $uid]);
        json_out(['contacts' => $st->fetchAll()]);

    case 'GET messages':
        $uid = require_auth();
        $with = filter_var($_GET['with'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        $after = filter_var($_GET['after'] ?? 0, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
        if (!$with || $after === false) {
            json_error('Paramètres invalides.');
        }
        // Autorisation : seuls les messages dont l'utilisateur connecté est expéditeur ou destinataire.
        $st = db()->prepare(
            'SELECT id, sender_id, receiver_id, iv, ciphertext, kind, created_at FROM messages
              WHERE id > :after AND ((sender_id = :me AND receiver_id = :other) OR (sender_id = :other2 AND receiver_id = :me2))
              ORDER BY id ASC LIMIT 200'
        );
        $st->execute(['after' => $after, 'me' => $uid, 'other' => $with, 'other2' => $with, 'me2' => $uid]);
        json_out(['messages' => $st->fetchAll()]);

    case 'POST send':
        $uid = require_auth();
        $in = json_input();
        $to = filter_var($in['to'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        $kind = $in['kind'] ?? '';
        if (!$to || $to === $uid || !in_array($kind, ['text', 'file'], true)) {
            json_error('Destinataire ou type invalide.');
        }
        $maxCipher = (int) ceil(($CONFIG['max_file_bytes'] + 4096) * 4 / 3);
        $iv = b64_field($in, 'iv', 24);
        $cipher = b64_field($in, 'ciphertext', $kind === 'file' ? $maxCipher : 200000);
        if (!user_row($to)) {
            json_error('Destinataire introuvable.', 404);
        }
        db()->prepare('INSERT INTO messages (sender_id, receiver_id, iv, ciphertext, kind, created_at) VALUES (?, ?, ?, ?, ?, ?)')
            ->execute([$uid, $to, $iv, $cipher, $kind, time()]);
        json_out(['id' => (int) db()->lastInsertId()], 201);

    case 'POST delete_conversation':
        $uid = require_auth();
        $in = json_input();
        $with = filter_var($in['with'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        if (!$with) {
            json_error('Paramètres invalides.');
        }
        $st = db()->prepare('DELETE FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)');
        $st->execute([$uid, $with, $with, $uid]);
        json_out(['deleted' => $st->rowCount()]);

    default:
        json_error('Action inconnue.', 404);
}
