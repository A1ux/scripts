# Infraestructure 

## Redirectors

### Apache HTTPS Redirector

#### Install

```bash
sudo apt install apache2
sudo a2enmod ssl rewrite proxy proxy_http
sudo systemctl restart apache2
```

#### Configuration

```bash
cd /etc/apache2/sites-enabled/
sudo rm 000-default.conf
sudo ln -s ../sites-available/default-ssl.conf .
sudo systemctl restart apache2
```

#### Generate certificates and configure

```bash
sudo certbot certonly --manual --preferred-challenges dns -d "*.domain.com" -d "domain.com"
# Modify default-ssl.conf
SSLCertificateFile     /etc/ssl/certs/certbot.pem
SSLCertificateKeyFile  /etc/ssl/private/certbot.key
```

#### SSH

```bash
scp localhost.crt attacker@10.10.0.100:/home/attacker/
sudo cp localhost.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
curl -v -k https://10.10.5.50
```

```bash
ssh -N -R 8443:localhost:443 attacker@10.10.0.100
```

#### Enabling Apache Redirection

```bash
# Modify /etc/apache2/sites-enabled/default-ssl.conf and add
<Directory /var/www/html/>
    Options Indexes FollowSymLinks MultiViews
    AllowOverride All
    Require all granted
</Directory>
# And underneath SSLEngine on, you can add
SSLProxyEngine on
# and if you have errors you can add also
SSLProxyVerify none
SSLProxyCheckPeerCN off
SSLProxyCheckPeerName off
SSLProxyCheckPeerExpire off
# restart apache2
sudo systemctl restart apache2
# create a new .htaccess file in the apache web root, /var/www/html
RewriteEngine on
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]
```

#### User Agent rules

```bash
# Create a page
echo "Nothing to see here..." | sudo tee /var/www/html/diversion
# And modify .htaccess
RewriteEngine on

RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a$ diversion [PT]

RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]
```

##### Autossh (team server config)


```bash
Host                 redirector-1
HostName             <https redirector>
User                 <user>
Port                 22
IdentityFile         </home/attacker/.ssh/id_rsa>
RemoteForward        8443 localhost:443
ServerAliveInterval  30
ServerAliveCountMax  3
# and run
autossh -M 0 -f -N redirector-1
```

## C2

### Certificates (localhost)

```bash
openssl req -x509 -nodes -newkey rsa:2048 -keyout localhost.key -out localhost.crt -sha256 -days 365 -subj '/CN=localhost'
```

#### Cobalt Strike

```bash
# For Cobalt Strike
openssl pkcs12 -inkey localhost.key -in localhost.crt -export -out localhost.pfx # Enter password
keytool -importkeystore -srckeystore localhost.pfx -srcstoretype pkcs12 -destkeystore localhost.store
# Copy localhost.store to /home/attacker/cobaltstrike/ and modify .profile
https-certificate {
     set keystore "localhost.store";
     set password "pass123";
}
```