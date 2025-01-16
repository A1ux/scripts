# Phishing 

## Evilginx

## Oneliners

### Download

https://github.com/kgretzky/evilginx2
https://github.com/kgretzky/gophish/

### Ejecutar

> Lanzar siempre sobre tmux para seguir ejecutando al finalizar conexion ssh

```bash
sudo ./evilginx -p ../phishlets
sudo ./evilginx -p ../phishlets -developer # para dev local
```

### Configs

> Now if you're not running a local development instance (started with -developer command line argument), Evilginx will start to automatically obtain the required TLS certificates from LetsEncrypt.

#### General config

```bash
# Set up a domain
config domain <domain.com>
config ipv4 <public ip>
config gophish admin_url https://localhost:3333/
config gophish api_key <API KEY>
config gophish insecure true
config unauth_url <https://organization.com>
config gophish test
```

#### Phishlets

Config templates for phishing

```bash
phishlets hostname <phishlet name> <domain.com>
phishlets enable <phishlet name>
phishlets disable <phishlet name>
phishlets get-hosts <phishlet name>
```

#### Lures

Config lure

> `0` is the ID of the lure

```bash
lures create <phishlet name>
lures edit 0 redirect_url https://www.alux.cc # page to redirect after get credentials or sessions
lures edit 0 path /login # Change default path
lures edit 0 redirector download_example # Add redirector, /redirectors directory
lures get-url <id lure>
lures get-url <id lure> name="John Doe" mail=test@mail.com anothervariable=test #Add variables that you can use in redirector 
```

##### Redirectors

Util for redirector in evilginx + gophish

| Variable     | Description      |
|--------------|------------------|
| `{fname}`    | First Name       |
| `{lname}`    | Last Name        |
| `{email}`    | Email Address    |

#### Sessions

```bash
sessions
sessions <id session>
```

#### Blacklist

```bash
blacklist noadd # BEst option if you dont want to block ips but do want to block malformed requests.
sudo nano /root/.evilginx/blacklist.txt # also you can add ips here or CIDRs
```

#### Proxy

```bash
proxy disable
proxy type <socks5, http, https, socks5>
proxy address <address>
proxy port <port>
proxy username <user>
proxy password <pass>
proxy enable
```

## Gophish

Variables for Gopshish email template


| Variable       | Description                                      |
|----------------|--------------------------------------------------|
| `{{.RId}}`     | The target's unique ID                          |
| `{{.FirstName}}` | The target's first name                        |
| `{{.LastName}}`  | The target's last name                         |
| `{{.Position}}`  | The target's position                          |
| `{{.Email}}`     | The target's email address                     |
| `{{.From}}`      | The spoofed sender                             |
| `{{.TrackingURL}}` | The URL to the tracking handler               |
| `{{.Tracker}}`   | An alias for `<img src="{{.TrackingURL}}"/>`   |
| `{{.URL}}`       | The phishing URL                               |
| `{{.BaseURL}}`   | The base URL with the path and rid parameter stripped. Useful for making links to static files. |

### Example template

```html
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Notificación de Seguridad</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            color: #333;
            background-color: #f9f9f9;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 600px;
            margin: 30px auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            padding: 20px 0;
        }
        h2 {
            color: #1a73e8;
        }
        .content {
            font-size: 16px;
            line-height: 1.5;
        }
        .cta {
            background-color: #1a73e8;
            color: white;
            padding: 15px 20px;
            text-decoration: none;
            border-radius: 5px;
            display: inline-block;
            margin-top: 20px;
        }
        .cta:hover {
            background-color: #155ab2;
        }
        .footer {
            margin-top: 20px;
            font-size: 12px;
            color: #888;
            text-align: center;
        }
        .footer a {
            color: #888;
            text-decoration: none;
        }
    </style>
</head>
<body>

    <div class="container">
        <div class="header">
            <h2>Alerta de Seguridad</h2>
        </div>
        <div class="content">
            <p>Estimado/a {{.FirstName}} {{.LastName}},</p>
            <p>Hemos detectado un inicio de sesión sospechoso en su cuenta asociada al correo electrónico <strong>{{.Email}}</strong>. Para proteger su seguridad, hemos suspendido temporalmente el acceso. Por favor, haga clic en el siguiente enlace para verificar su identidad y restaurar el acceso a su cuenta:</p>
            <a href="{{.URL}}" class="cta">Verificar mi cuenta</a>
            <p>Si no ha solicitado este acceso, por favor ignore este mensaje.</p>
        </div>
        <div class="footer">
            <p>Este es un mensaje automático. No responda a este correo.</p>
            <p>Variable

                Description
                
                {{.RId}}
                
                The target's unique ID
                
                {{.FirstName}}
                
                The target's first name
                
                {{.LastName}}
                
                The target's last name
                
                {{.Position}}
                
                The target's position
                
                {{.Email}}
                
                The target's email address
                
                {{.From}}
                
                The spoofed sender
                
                {{.TrackingURL}}
                
                The URL to the tracking handler
                
                {{.Tracker}}
                
                An alias for <img src="{{.TrackingURL}}"/>
                
                {{.URL}}
                
                The phishing URL
                
                {{.BaseURL}}
                
                The base URL with the path and rid parameter stripped. Useful for making links to static files.</p>
        </div>
    </div>

</body>
</html>
```


- https://github.com/An0nUD4Y/Evilginx2-Phishlets
- https://github.com/simplerhacking/Evilginx3-Phishlets
- https://github.com/hash3liZer/phishlets
- https://github.com/ArchonLabs/evilginx2-phishlets
- https://github.com/charlesbel/Evilginx2-Phishlets
