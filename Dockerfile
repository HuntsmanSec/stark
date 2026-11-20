FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY stark ./stark
RUN pip install --no-cache-dir . && useradd -m stark
USER stark
ENTRYPOINT ["stark"]
CMD ["--help"]
