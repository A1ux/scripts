# Bloodhound & Cypher Oneliners


## Excepciones a la politica de contrasenas de usuarios de Dominio

Cuando la request de powershell es excedida

```
MATCH (n:User) 
RETURN n.samaccountname AS samaccountname,n.displayname AS name, n.enabled AS enabled, n.pwdneverexpires AS passwordneverexpires
```

## Marcar usuario como owned

```
MATCH (u:User {name: 'NombreDelUsuario'})
SET u.owned = true
RETURN u
```