FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY stark ./stark
RUN pip install --no-cache-dir . && useradd -m stark && mkdir -p /data && chown stark /data
USER stark
# Everything you create (accounts, API keys, cases, settings, CLI config) lives in /data.
# Keep it on a named volume so it survives image updates: docker run -v stark-data:/data ...
ENV STARK_DATA_DIR=/data \
    STARK_CONFIG=/data/config.toml \
    STARK_CACHE_DIR=/data/cache \
    STARK_IN_DOCKER=1
VOLUME ["/data"]
EXPOSE 8765
ENTRYPOINT ["stark"]
# Team server by default; put it behind an HTTPS reverse proxy.
CMD ["serve", "--host", "0.0.0.0", "--port", "8765", "--no-browser", "--secure-cookies"]
