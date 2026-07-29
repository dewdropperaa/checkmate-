FROM ghcr.io/zaproxy/zaproxy:2.17.0@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2

COPY zap-entrypoint.sh /zap-entrypoint.sh
RUN chmod +x /zap-entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/zap-entrypoint.sh"]
