# Locust 


## Install


```bash
pip3 install locust
```

## Config

| Parameter | Desc | 
|----------|----------|
| -f | The Python file or module that contains your test |
| --web-port    | Port on which to run web host   |
| --headless    | Disable the web interface   |
| --web-login    | Protects the web interface with a login page   |
| --web-host | Host to bind the web interface to |
| --master | Launch locust as a master node, to which worker nodes connect. |
| --master-host | Hostname of locust master node to connect to |
| --master-port | Port to connect to on master node. | 
| --loglevel | Choose between DEBUG/INFO/WARNING/ERROR/CRITICAL |
| --logfile | Path to log file. If not set, log will go to stderr |


## Attack

```bash
# Server Locust
locust --master -f rutas.py
# Worker Locust
locust -f server/rutas.py --master-host 192.168.123.45 --worker
```