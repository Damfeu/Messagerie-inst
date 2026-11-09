#!/usr/bin/env bash
# D-Send v2 — rejoue côté serveur les attaques qui fonctionnaient sur la v1.
# Usage : BASE_URL=http://localhost:8000 bash tests/securite.sh
set -u
B="${BASE_URL:-http://localhost:8000}"
J='Content-Type: application/json'
fail=0
expect() { if echo "$2" | grep -q "$3"; then echo "  OK    $1"; else echo "  ÉCHEC $1 → $2"; fail=1; fi; }
jar=$(mktemp)

expect "cookie id=2 forgé (usurpation v1)" "$(curl -s -b 'id=2' "$B/api.php?action=messages&with=1")" "Session expirée"
expect "écriture via GET refusée"          "$(curl -s "$B/api.php?action=send&to=1&text=x")" "Action inconnue"
expect "POST sans jeton CSRF refusé"       "$(curl -s -X POST -H "$J" -d '{"email":"x@y.z"}' "$B/api.php?action=prelogin")" "Jeton de sécurité invalide"
expect "contacts sans session refusés"     "$(curl -s "$B/api.php?action=contacts")" "Session expirée"

csrf=$(curl -s -c "$jar" "$B/api.php?action=session" | sed -E 's/.*"csrf":"([a-f0-9]+)".*/\1/')
email="force-brute-$RANDOM@test.local"
for i in 1 2 3 4 5; do curl -s -o /dev/null -b "$jar" -X POST -H "$J" -H "X-CSRF-Token: $csrf" -d "{\"email\":\"$email\",\"auth_secret\":\"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=\"}" "$B/api.php?action=login"; done
expect "6e tentative de connexion bloquée" "$(curl -s -b "$jar" -X POST -H "$J" -H "X-CSRF-Token: $csrf" -d "{\"email\":\"$email\",\"auth_secret\":\"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=\"}" "$B/api.php?action=login")" "Trop de tentatives"

headers=$(curl -sI "$B/")
expect "Content-Security-Policy présente" "$headers" "Content-Security-Policy"
expect "X-Frame-Options présent"          "$headers" "X-Frame-Options"
expect "cookie de session HttpOnly"       "$headers" "HttpOnly"

rm -f "$jar"
[ $fail -eq 0 ] && echo "Tous les contrôles passent." || echo "Des contrôles ont échoué."
exit $fail
