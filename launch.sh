#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR" || exit 1

echo ""
echo "  NetWatch Next Core"
echo "  Lean live globe, investigation, tools, and data console"
echo ""

PYTHON="$(command -v python3 || command -v python)"
if [ -z "$PYTHON" ]; then
  echo "  Python 3 is required."
  exit 1
fi

echo "  Python: $($PYTHON --version 2>&1)"

$PYTHON -c "import flask, psutil" >/dev/null 2>&1 || {
  echo "  Installing minimal dependencies..."
  "$PYTHON" -m pip install flask psutil >/dev/null 2>&1 || {
    echo "  Could not install flask/psutil."
    exit 1
  }
}

if [ "$EUID" -eq 0 ]; then
  echo "  Mode: root live capture enabled"
else
  echo "  Mode: safe local mode"
  echo "  Tip: run with sudo for tcpdump-backed live packet capture."
fi

if command -v lsof >/dev/null 2>&1; then
  PIDS="$(lsof -tiTCP:5001 -sTCP:LISTEN 2>/dev/null)"
  if [ -n "$PIDS" ]; then
    if [ "$EUID" -eq 0 ]; then
      echo "  Stopping old server on port 5001..."
      echo "$PIDS" | xargs kill -9 >/dev/null 2>&1
      sleep 1
    else
      echo "  Port 5001 is already in use."
      echo "  Stop the old server first, or rerun with sudo so launch.sh can replace it."
      exit 1
    fi
  fi
fi

echo ""
echo "  Dashboard: http://localhost:5001"
echo "  Keep this terminal open while NetWatch is running."
echo ""

(sleep 2 && open "http://localhost:5001") >/dev/null 2>&1 &
exec "$PYTHON" app.py
