#!/bin/bash
# pi-app-store: 1
set -eu
cd -- "$(dirname -- "$0")"
case "${1:-}" in
  install) command -v python3 >/dev/null
    sed '1,/^#PYTHON-BELOW$/d' dropit.sh > .app-store-dropit-check.py
    python3 -m py_compile .app-store-dropit-check.py
    rm -f .app-store-dropit-check.py ;;
  run) exec sh dropit.sh ;;
  *) echo "Use: bash app-store.sh install OR bash app-store.sh run"; exit 1 ;;
esac
