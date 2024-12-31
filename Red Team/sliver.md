# Sliver

## HTTPS

```bash
openssl req -x509 -nodes -newkey rsa:2048 -keyout localhost.key -out localhost.crt -sha256 -days 365 -subj '/CN=localhost'
https -c /home/alux/research/c2/sliver/localhost.crt -k /home/alux/research/c2/sliver/localhost.key -L 192.168.1.71 -l 443
```

## Website

```bash
websites add-content -c /home/alux/research/c2/sliver/webserver -p / -w fake-web
```