#!/bin/sh
if [ ! -f /data/rules.json ]; then
  cp /opt/sift/rules.json.example /data/rules.json
fi
exec python3 /opt/sift/sidecar.py /data/config.json
