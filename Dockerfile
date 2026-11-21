FROM python:3.11-slim

WORKDIR /opt/sift
COPY board.html ui.html ./
COPY board.py hello.py report.py settings.py sidecar.py spamcore.py ui.py ./
COPY shapes.json shapes.seed.json rules.json.example ./
COPY shapes ./shapes
COPY start-sidecar.sh start-page.sh ./
RUN chmod 755 /opt/sift/start-sidecar.sh /opt/sift/start-page.sh

ENV SIFT_DIR=/data
EXPOSE 8093 8337

CMD ["/opt/sift/start-sidecar.sh"]
