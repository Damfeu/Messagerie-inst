<?php
/*
 * Copiez ce fichier en config.php et adaptez-le.
 * config.php est ignoré par Git : ne publiez jamais vos identifiants.
 */
return [
    // MySQL en production :
    // 'db' => ['dsn' => 'mysql:host=localhost;dbname=dsend;charset=utf8mb4', 'user' => 'dsend', 'password' => '...'],
    // SQLite pour un essai local :
    'db' => ['dsn' => 'sqlite:' . __DIR__ . '/../storage/dsend.sqlite', 'user' => null, 'password' => null],

    // Secret aléatoire (64 caractères hex). Générez-le avec : php -r "echo bin2hex(random_bytes(32));"
    'app_secret' => 'change-moi-avant-la-mise-en-production',

    // Taille maximale d'une pièce jointe chiffrée, en octets.
    'max_file_bytes' => 8 * 1024 * 1024,
];
