FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /portail
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY demarrer.sh .
RUN useradd -r -u 10001 -d /donnees siem && mkdir -p /donnees /certs && chown siem /donnees
USER siem
ENV SIEM_BASE=/donnees/siem.db
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import ssl,urllib.request;urllib.request.urlopen('https://127.0.0.1:8443/api/sante',context=ssl._create_unverified_context())"
CMD ["./demarrer.sh"]
