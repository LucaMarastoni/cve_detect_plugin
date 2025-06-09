#!/usr/bin/env bash
set -euo pipefail

# Nome della cartella del virtualenv
VENV_DIR=".venv"

# Se non esiste, lo creo
if [ ! -d "$VENV_DIR" ]; then
  echo "Creo il virtual environment '$VENV_DIR'..."
  python3 -m venv "$VENV_DIR"
fi

# Attivazione virtualenv
echo "Attivo il virtual environment '$VENV_DIR'..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# Controllo requirements.txt
REQ_FILE="requirements.txt"
if [ ! -f "$REQ_FILE" ]; then
  echo "File '$REQ_FILE' non trovato."
  deactivate
  exit 1
fi

# Installazione dipendenze
echo "Installazione delle dipendenze da '$REQ_FILE'..."
pip install --upgrade pip
pip install -r "$REQ_FILE"

python3 ./cve_monitor.py