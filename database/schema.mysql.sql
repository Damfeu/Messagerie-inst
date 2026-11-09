-- D-Send v2 — schéma MySQL / MariaDB
-- Le serveur ne stocke que des données chiffrées côté client : aucune clé privée en clair,
-- aucun texte de message, aucun nom de fichier lisible.

CREATE TABLE users (
    id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email             VARCHAR(190) NOT NULL UNIQUE,
    auth_hash         VARCHAR(255) NOT NULL,      -- Argon2id d'un secret dérivé du mot de passe (le mot de passe n'est jamais envoyé)
    kdf_salt          VARCHAR(64)  NOT NULL,      -- sel PBKDF2 utilisé dans le navigateur
    public_key        TEXT         NOT NULL,      -- clé publique ECDH P-256 (SPKI, base64)
    enc_private_key   TEXT         NOT NULL,      -- clé privée chiffrée en AES-256-GCM par le navigateur
    private_key_iv    VARCHAR(32)  NOT NULL,
    color             VARCHAR(16)  NOT NULL,
    created_at        INT UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE messages (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sender_id    INT UNSIGNED NOT NULL,
    receiver_id  INT UNSIGNED NOT NULL,
    iv           VARCHAR(32)  NOT NULL,
    ciphertext   LONGTEXT     NOT NULL,           -- texte, ou fichier + nom, chiffrés ensemble
    kind         ENUM('text','file') NOT NULL,
    created_at   INT UNSIGNED NOT NULL,
    INDEX idx_pair (sender_id, receiver_id, id),
    INDEX idx_receiver (receiver_id, id),
    FOREIGN KEY (sender_id)   REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE login_attempts (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    attempt_key   CHAR(64)     NOT NULL,          -- HMAC(e-mail + IP) : rien n'est stocké en clair
    attempted_at  INT UNSIGNED NOT NULL,
    INDEX idx_key (attempt_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
