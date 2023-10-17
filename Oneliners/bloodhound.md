# Bloodhound Oneliners


## Excepciones a la politica de contrasenas de usuarios de Dominio

```
MATCH (n:User) 
RETURN n.samaccountname AS samaccountname,n.displayname AS name, n.enabled AS enabled, n.pwdneverexpires AS passwordneverexpires
```

