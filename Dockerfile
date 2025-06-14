FROM registry.millegrilles.com/millegrilles/web_python:2025.4.57 as stage1

ENV CA_PATH=/var/opt/millegrilles/configuration/pki.millegrille.cert \
    CERT_PATH=/var/opt/millegrilles/secrets/pki.webauth.cert \
    KEY_PATH=/var/opt/millegrilles/secrets/pki.webauth.cle \
    MQ_HOSTNAME=mq \
    MQ_PORT=5673 \
    REDIS_HOSTNAME=redis \
    REDIS_PASSWORD_PATH=/var/run/secrets/passwd.redis.txt \
    WEB_PORT=1443

COPY . $BUILD_FOLDER

RUN cd $BUILD_FOLDER && \
    python3 ./setup.py install

# UID fichiers = 984
# GID millegrilles = 980
USER 984:980

CMD ["-m", "millegrilles_webauth"]
# CMD ["-m", "millegrilles_webauth", "--verbose"]
