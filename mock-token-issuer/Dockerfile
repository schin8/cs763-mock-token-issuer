FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir cryptography
COPY mock_issuer.py .
ENV KEYS_DIR=/app/keys \
    ISSUER=http://localhost:9000 \
    AUDIENCE=cs763-api \
    ALG=RS256 \
    PORT=9000
EXPOSE 9000
# Keys are generated on first start if /app/keys is empty.
# Mount a volume at /app/keys to keep the same keys across restarts.
CMD ["python", "mock_issuer.py", "serve"]
