#!/bin/bash
# KinderKompas — Start script
cd "$(dirname "$0")"
echo "🌿 KinderKompas opstarten..."
python3 -c "import flask" 2>/dev/null || pip3 install flask werkzeug --break-system-packages
mkdir -p uploads
echo "✅ http://localhost:5000"
echo "beheerder@kdv.nl / admin123"
python3 server.py
