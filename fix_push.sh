#!/bin/bash

set -e  # Beendet das Skript bei einem Fehler

# Variablen
BRANCH="main"
REMOTE="origin"

echo "Sichere ungesicherte Änderungen (falls vorhanden)..."
git add .
if ! git diff --cached --quiet; then
    git commit -m "WIP: Temporärer Commit für ungesicherte Änderungen"
    STASHED=true
else
    STASHED=false
fi

echo "Hole und rebase die neuesten Änderungen von $REMOTE/$BRANCH..."
git pull --rebase $REMOTE $BRANCH

echo "Pushen der lokalen Änderungen zu $REMOTE/$BRANCH..."
git push $REMOTE $BRANCH

if [ "$STASHED" = true ]; then
    echo "Entferne temporären Commit..."
    git reset HEAD~1
    echo "Ungesicherte Änderungen wiederherstellen..."
    git stash pop
fi

echo "Push erfolgreich abgeschlossen."
