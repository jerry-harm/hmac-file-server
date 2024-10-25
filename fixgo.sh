#!/bin/bash

# Beende das Skript bei einem Fehler
set -e

GO_MOD_FILE="go.mod"
BACKUP_FILE="go.mod.bak"

echo "=== Start des Fix-Skripts ==="

# Schritt 1: Überprüfen, ob go.mod existiert
if [ ! -f "$GO_MOD_FILE" ]; then
    echo "Fehler: $GO_MOD_FILE wurde nicht gefunden im aktuellen Verzeichnis."
    exit 1
fi

# Schritt 2: Backup der go.mod erstellen
echo "Erstelle ein Backup von $GO_MOD_FILE als $BACKUP_FILE..."
cp "$GO_MOD_FILE" "$BACKUP_FILE"

# Schritt 3: Entferne alle 'toolchain'-Direktiven aus go.mod
echo "Entferne alle 'toolchain'-Direktiven aus $GO_MOD_FILE..."
sed -i '/^toolchain/d' "$GO_MOD_FILE"

# Schritt 4: Setze die Go-Version auf 1.21, falls nicht bereits gesetzt
if grep -q '^go ' "$GO_MOD_FILE"; then
    echo "Setze die Go-Version auf 1.21..."
    sed -i 's/^go .*/go 1.21/' "$GO_MOD_FILE"
else
    echo "Füge 'go 1.21' zu $GO_MOD_FILE hinzu..."
    echo "go 1.21" >> "$GO_MOD_FILE"
fi

# Schritt 5: Entferne weitere Referenzen zu 'go1.22' in go.mod
echo "Ersetze alle Vorkommen von 'go1.22' mit 'go1.21' in $GO_MOD_FILE..."
sed -i 's/go1\.22/go1.21/g' "$GO_MOD_FILE"

# Schritt 6: Führe go mod tidy aus
echo "Führe 'go mod tidy' aus..."
go mod tidy

# Schritt 7: Änderungen zur Git-Stage hinzufügen
echo "Füge Änderungen zu Git hinzu..."
git add "$GO_MOD_FILE" go.sum

# Schritt 8: Überprüfen, ob es etwas zum Committen gibt
if git diff --cached --quiet; then
    echo "Keine Änderungen zum Committen."
else
    # Schritt 9: Committe die Änderungen
    echo "Committe die Änderungen..."
    git commit -m "fix: setze Go-Version auf 1.21 und entferne toolchain-Direktive"
fi

# Schritt 10: Hole die neuesten Änderungen vom Remote-Repository mit Rebase
echo "Hole die neuesten Änderungen von origin/main und führe ein Rebase durch..."
git pull --rebase origin main

# Schritt 11: Pushe die Änderungen zum Remote-Repository
echo "Pushe die Änderungen zu origin/main..."
git push origin main

echo "=== Fix-Skript erfolgreich abgeschlossen ==="
