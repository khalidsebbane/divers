FROM python:3.12-slim
WORKDIR /portail
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY demarrer.sh .
RUN useradd -r -u 10001 siem && mkdir /donnees && chown siem /donnees
USER siem
EXPOSE 8443
HEALTHCHECK CMD python -c "import urllib.request,ssl;urllib.request.urlopen('https://127.0.0.1:8443/api/sante',context=ssl._create_unverified_context())" || python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8443/api/sante')"
CMD ["./demarrer.sh"]
