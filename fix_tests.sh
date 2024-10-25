#!/bin/bash

set -e  # Beende das Skript bei einem Fehler

# -----------------------------
# Konfigurationsvariablen
# -----------------------------

# Pfad zur config.toml
CONFIG_FILE="cmd/server/config.toml"

# Inhalt der config.toml für Tests
read -r -d '' CONFIG_CONTENT << EOM
[server]
StoreDir = "./testdata"
RedisAddr = "localhost:6379"
RedisPassword = "testpassword"

# Weitere Test-Konfigurationen...
EOM

# -----------------------------
# Funktionen
# -----------------------------

# Funktion zur Erstellung der config.toml
create_config() {
    echo "Überprüfe, ob $CONFIG_FILE existiert..."

    if [ -f "$CONFIG_FILE" ]; then
        echo "$CONFIG_FILE existiert bereits. Überspringe Erstellung."
    else
        echo "$CONFIG_FILE wurde nicht gefunden. Erstelle die Datei mit Testkonfigurationen..."
        mkdir -p "$(dirname "$CONFIG_FILE")"
        echo "$CONFIG_CONTENT" > "$CONFIG_FILE"
        echo "$CONFIG_FILE wurde erfolgreich erstellt."
    fi
}

# Funktion zur Ausführung der Tests
run_tests() {
    echo "Führe Go-Tests mit 'go test ./... -v' aus..."
    go test ./... -v
    echo "Go-Tests wurden erfolgreich ausgeführt."
}

# Funktion zur Bereinigung nach Tests (optional)
cleanup() {
    echo "Bereinige Testdaten im Verzeichnis ./testdata..."
    rm -rf ./testdata
    echo "Testdaten wurden erfolgreich bereinigt."
}

# -----------------------------
# Hauptskriptausführung
# -----------------------------

echo "Starte das Fix-Skript für Go-Tests..."

# Schritt 1: Erstelle die config.toml, falls nicht vorhanden
create_config

# Schritt 2: Führe die Tests aus
run_tests

# Schritt 3: (Optional) Bereinige nach Tests
# Uncomment the following line, wenn du nach den Tests bereinigen möchtest
# cleanup

echo "Fix-Skript wurde erfolgreich abgeschlossen."

exit 0
