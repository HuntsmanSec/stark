FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY stark ./stark
RUN pip install --no-cache-dir . && useradd -m stark && mkdir -p /data && chown stark /data
USER stark
ENV STARK_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8765
ENTRYPOINT ["stark"]
# Team server by default; put it behind an HTTPS reverse proxy.
CMD ["serve", "--host", "0.0.0.0", "--port", "8765", "--no-browser", "--secure-cookies"]
