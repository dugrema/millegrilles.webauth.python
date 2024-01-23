# Authentification web

<pre>
CA_PEM=/var/opt/millegrilles/configuration/pki.millegrille.cert
CERT_PEM=/var/opt/millegrilles/secrets/pki.webauth.cert
KEY_PEM=/var/opt/millegrilles/secrets/pki.webauth.cle
MQ_HOSTNAME=localhost
REDIS_HOSTNAME=localhost
REDIS_PASSWORD_PATH=/var/opt/millegrilles/secrets/passwd.redis.txt
WEB_PORT=4005
</pre>

## Modifier nginx

/var/opt/millegrilles/nginx/modules/webauth.proxypass

Changer `SERVER` pour le hostname local (ou IP local pour mode offline).

docker service update --force nginx
