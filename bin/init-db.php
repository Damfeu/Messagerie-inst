<?php
// Crée les tables. Usage : php bin/init-db.php
$CONFIG = require (is_file(__DIR__ . '/../config/config.php') ? __DIR__ . '/../config/config.php' : __DIR__ . '/../config/config.example.php');
$pdo = new PDO($CONFIG['db']['dsn'], $CONFIG['db']['user'] ?? null, $CONFIG['db']['password'] ?? null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$file = str_starts_with($CONFIG['db']['dsn'], 'sqlite:') ? 'schema.sqlite.sql' : 'schema.mysql.sql';
$pdo->exec(file_get_contents(__DIR__ . '/../database/' . $file));
echo "Base initialisée ($file).\n";
