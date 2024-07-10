# Elastic EDR Install

## Elastic Search

### Install

```bash
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch |sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update
sudo apt install elasticsearch
```

### Configure

```bash
sudo nano /etc/elasticsearch/elasticsearch.yml
### Comment
#network.host: 192.168.0.1
#http.port: 9200
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch
curl -X GET -k https://localhost:9200
curl -X GET -k https://elastic:password@localhost:9200
```

## Kibana

### Install


```bash
sudo apt install kibana
```

### Config

```bash
/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
## Copy token
/usr/share/kibana/bin/kibana-setup 
## Paste token
systemctl start kibana
systemctl enable kibana
ss -tulpn | grep 5601
```

```bash
/usr/share/kibana/bin/kibana-encryption-keys generate
## Copy settings xpack
nano /etc/kibana/kibana.yml
## Paste settings xpack
systemctl restart kibana
```

## Nginx

### Install

```bash
sudo apt install nginx
```

### Config

```bash
sudo nano /etc/nginx/sites-enabled/default
## Modify location
location / {
                proxy_pass http://127.0.0.1:5601;
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                #try_files $uri $uri/ =404;
## Restart and enable nginx
sudo systemctl restart nginx
sudo systemctl enable nginx
```

## Fleet and Agent Installation

### Fleet Server

1. Log in to http://ip/
2. Use elastic's credentials
3. Go to Integrations
4. Add Fleet Server
5. Download cert to fleet server

EDR Server

```bash
cd /etc/elasticsearch/certs/
python3 -m http.server 8009
```

Fleet Server

```bash
sudo mkdir -p /usr/local/etc/ssl/certs/elastic/
cd /usr/local/etc/ssl/certs/elastic/
wget http://edrserver/http_ca.crt
```

Add fleet server and add to the end

```bash
--fleet-server-es-ca=/usr/local/etc/ssl/certs/elastic/http_ca.crt --insecure
```


### Agent

Add agent and add to the end

```bash
--insecure
```

### Extensions

1. Install all rules on Kibana Alerts (Elastic Rules)
2. Install Windows Integrations
3. Install Endpoint Security
4. Instal Linux Integrations

### Troubleshooting 

#### Paquetes errores

```json
PUT /_security/role/custom_superuser
{
  "cluster": [
    "all"
  ],
  "indices": [
    {
      "names": [
        "*"
      ],
      "privileges": [
        "all"
      ],
      "allow_restricted_indices": true
    },
    {
      "names": [
        "*"
      ],
      "privileges": [
        "monitor",
        "read",
        "view_index_metadata",
        "read_cross_cluster"
      ],
      "allow_restricted_indices": true
    }
  ],
  "applications": [
    {
      "application": "*",
      "privileges": [
        "*"
      ],
      "resources": [
        "*"
      ]
    }
  ],
  "run_as": [
    "*"
  ],
  "metadata": {},
  "transient_metadata": {},
  "remote_indices": [
    {
      "names": [
        "*"
      ],
      "privileges": [
        "all"
      ],
      "allow_restricted_indices": true,
      "clusters": [
        "*"
      ]
    },
    {
      "names": [
        "*"
      ],
      "privileges": [
        "monitor",
        "read",
        "view_index_metadata",
        "read_cross_cluster"
      ],
      "allow_restricted_indices": true,
      "clusters": [
        "*"
      ]
    }
  ]
}
```

### References

- 