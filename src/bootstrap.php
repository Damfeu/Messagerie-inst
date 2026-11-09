<?php
declare(strict_types=1);

/*
 * D-Send v2 — amorçage commun : configuration, base de données, session durcie,
 * en-têtes de sécurité, protection CSRF et réponses JSON.
 */

$configFile = __DIR__ . '/../config/config.php';
if (!is_file($configFile)) {
    $configFile = __DIR__ . '/../config/config.example.php';
}
$CONFIG = require $configFile;

// Tests : avec le serveur intégré de PHP uniquement, DSEND_TEST_DB=test.sqlite utilise une base
// séparée dans storage/, pour ne jamais toucher à la vraie base. Sans effet sous Apache/Nginx.
$testDb = getenv('DSEND_TEST_DB');
if (PHP_SAPI === 'cli-server' && is_string($testDb) && preg_match('/^[\w-]+\.sqlite$/', $testDb)) {
    $CONFIG['db'] = ['dsn' => 'sqlite:' . __DIR__ . '/../storage/' . $testDb, 'user' => null, 'password' => null];
}

/* ---------- En-têtes de sécurité (OWASP A05) ---------- */
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()');
header('Cross-Origin-Opener-Policy: same-origin');
if (is_https()) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

function is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
}

/* ---------- Base de données ---------- */
function db(): PDO
{
    static $pdo = null;
    global $CONFIG;
    if ($pdo === null) {
        $pdo = new PDO($CONFIG['db']['dsn'], $CONFIG['db']['user'] ?? null, $CONFIG['db']['password'] ?? null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        if (str_starts_with($CONFIG['db']['dsn'], 'sqlite:')) {
            $pdo->exec('PRAGMA foreign_keys = ON');
            // Essai local : les tables sont créées automatiquement au premier lancement.
            if (!$pdo->query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'")->fetchColumn()) {
                $pdo->exec(file_get_contents(__DIR__ . '/../database/schema.sqlite.sql'));
            }
        }
    }
    return $pdo;
}

/* ---------- Session durcie (OWASP A07) ---------- */
session_name('dsend_sid');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => is_https(),
    'httponly' => true,
    'samesite' => 'Strict',
]);
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_start();

const SESSION_IDLE_SECONDS = 1800; // 30 minutes d'inactivité

if (isset($_SESSION['uid'])) {
    if (time() - ($_SESSION['last_seen'] ?? 0) > SESSION_IDLE_SECONDS) {
        session_unset();
        session_regenerate_id(true);
    } else {
        $_SESSION['last_seen'] = time();
    }
}

function current_user_id(): ?int
{
    return isset($_SESSION['uid']) ? (int) $_SESSION['uid'] : null;
}

function login_user(int $id): void
{
    session_regenerate_id(true); // empêche la fixation de session
    $_SESSION['uid'] = $id;
    $_SESSION['last_seen'] = time();
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

function logout_user(): void
{
    $_SESSION = [];
    session_regenerate_id(true);
    session_destroy();
}

/* ---------- CSRF (OWASP A01) ---------- */
function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function require_csrf(): void
{
    $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($sent) || !hash_equals(csrf_token(), $sent)) {
        json_error('Jeton de sécurité invalide. Rechargez la page.', 403);
    }
}

/* ---------- JSON ---------- */
function json_out(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function json_error(string $message, int $status = 400): never
{
    json_out(['error' => $message], $status);
}

function json_input(): array
{
    $raw = file_get_contents('php://input', false, null, 0, 20 * 1024 * 1024);
    $data = json_decode($raw ?: '', true);
    if (!is_array($data)) {
        json_error('Requête invalide.');
    }
    return $data;
}

/* ---------- Validation ---------- */
function b64_field(array $in, string $key, int $maxLen): string
{
    $v = $in[$key] ?? null;
    if (!is_string($v) || $v === '' || strlen($v) > $maxLen || !preg_match('#^[A-Za-z0-9+/]+={0,2}$#', $v)) {
        json_error("Champ « $key » invalide.");
    }
    return $v;
}

/* ---------- Limitation des tentatives (OWASP A07) ---------- */
function attempt_key(string $email): string
{
    global $CONFIG;
    // Ni l'adresse IP ni l'e-mail ne sont stockés en clair.
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    return hash_hmac('sha256', strtolower($email) . '|' . $ip, $CONFIG['app_secret']);
}

function too_many_attempts(string $email): bool
{
    db()->prepare('DELETE FROM login_attempts WHERE attempted_at < ?')->execute([time() - 900]);
    $st = db()->prepare('SELECT COUNT(*) FROM login_attempts WHERE attempt_key = ?');
    $st->execute([attempt_key($email)]);
    return (int) $st->fetchColumn() >= 5;
}

function record_failed_attempt(string $email): void
{
    db()->prepare('INSERT INTO login_attempts (attempt_key, attempted_at) VALUES (?, ?)')
        ->execute([attempt_key($email), time()]);
}

function clear_attempts(string $email): void
{
    db()->prepare('DELETE FROM login_attempts WHERE attempt_key = ?')->execute([attempt_key($email)]);
}

function password_algo(): string|int
{
    return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
}
