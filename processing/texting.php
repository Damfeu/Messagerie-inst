<?php

require_once("../config/database.php");


$messagesStatement = $conn->prepare("INSERT INTO messages (sender_id, receiver_id, text, created_at) VALUES (:sender_id, :receiver_id, :text, :created_at)");
$messagesStatement->execute([
    "sender_id"=> $_COOKIE["id"],
    "receiver_id"=> $_GET["id"],
    "text"=> $_GET["text"],
    "created_at" => time()
]);



