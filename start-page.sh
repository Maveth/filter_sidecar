#!/bin/sh
if [ ! -f /data/rules.json ]; then
  cp /opt/sift/rules.json.example /data/rules.json
fi
port="${SIFT_PAGE_PORT:-8093}"
exec python3 /opt/sift/ui.py /data/rules.json "$port" /data/sidecar.log 0.0.0.0
