# Bloodhound & Cypher Oneliners


## Usuario

### Obtener usuario y descripcion

```c
MATCH (u:User)
RETURN u.samAccountName, u.description
```

### Admins del Dominio

> Usar mayuscula y en espanol "ADMINS. DEL DOMINIO"

```c
MATCH (u:User)-[:MemberOf]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.COM'})
return u.name, u.displayname
```

### Permisos de usuarios owned

```c
MATCH (u:User {owned:true})
OPTIONAL MATCH (u)-[r:HasSession|AdminTo|AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword]->(n)
RETURN u.name AS Usuario, labels(n) AS TipoDeNodo, type(r) AS TipoDePermiso, n.name AS NombreNodo
```

### Buscar nodos de usuario donde el nombre de la propiedad contiene el texto "admin", y luego devolver las propiedades de nombre, nombre para mostrar y descripción para cualquier coincidencia

```c
MATCH (u:User) WHERE u.name CONTAINS "ADMIN"
return u.name, u.displayname, u.description
```

### Mostrar todos los usuarios que son administradores en más de una máquina

```c
MATCH (u:User)-[:AdminTo]->(c:Computer)
WITH u, count(c) AS NumComputers
WHERE NumComputers > 1
RETURN u.name AS UserName, NumComputers
ORDER BY NumComputers DESC
```

### Mostrar los usuarios owned que son administradores de una maquina

```c
MATCH (u:User {owned:true})-[:AdminTo]->(c:Computer)
RETURN u.name AS OwnedAdminUser, collect(c.name) AS ComputersWhereAdmin
```

### Listar de usuarios únicos con una ruta (sin ruta "GetChanges", sin "CanRDP") a un grupo etiquetado como "highvalue" 

```c
MATCH (u:User)
MATCH (g:Group {highvalue: True})
MATCH p = shortestPath((u:User)-[r:AddMember|AdminTo|AllExtendedRights|AllowedToDelegate|Contains|ExecuteDCOM|ForceChangePassword|GenericAll|GenericWrite|GetChangesAll|GpLink|HasSession|MemberOf|Owns|ReadLAPSPassword|TrustedBy|WriteDacl|WriteOwner*1..]->(g))
RETURN DISTINCT(u.name),u.enabled
order by u.name
```

### Mostrar la cantidad de usuarios que tienen derechos de administrador en cada computadora, en orden descendente

```c
MATCH (c:Computer) OPTIONAL
MATCH (u1:User)-[:AdminTo]->(c) OPTIONAL
MATCH (u2:User)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c) WITH COLLECT(u1) + COLLECT(u2) AS tempVar,c UNWIND tempVar AS admins
RETURN c.name AS computerName,COUNT(DISTINCT(admins)) AS adminCount
ORDER BY adminCount DESC
```

### Usuarios kerberoasteables con mas privilegios

```c
MATCH (u:User {hasspn:true})
OPTIONAL MATCH (u)-[:AdminTo]->(c1:Computer)
OPTIONAL MATCH (u)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c2:Computer) WITH u,COLLECT(c1) + COLLECT(c2) AS tempVar UNWIND tempVar AS comps
RETURN u.name,COUNT(DISTINCT(comps))
ORDER BY COUNT(DISTINCT(comps)) DESC
```


### Excepciones a la politica de contrasenas de usuarios de Dominio

`=DATE(1970,1,1) + (A1 / 86400)`

Cuando la request de powershell es excedida

```c
MATCH (n:User) 
RETURN n.samaccountname AS samaccountname,n.displayname AS name, n.enabled AS enabled, n.pwdneverexpires AS passwordneverexpires
```

### Excepciones a la politica de contrasenas de administradores de Dominio

```c
MATCH (n:User)-[:MemberOf*1..2]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.COM'})
RETURN n.samaccountname, n.displayname, n.enabled, n.pwdlastset
```

### Sacar los usuarios que no son AdminCount 1, tienen generic all y no tienen admin local .

```c
MATCH (u:User)-[:GenericAll]->(c:Computer) WHERE  NOT u.admincount AND NOT (u)-[:AdminTo]->(c) RETURN u.name, c.name
```

### Marcar usuario como owned

```c
MATCH (u:User {name: 'NombreDelUsuario'})
SET u.owned = true
RETURN u
```

## Grupos

### Devolver los grupos cuyo nombre contiene la cadena "ADM".

```c
MATCH (g:Group)
WHERE g.name =~ '(?i).*ADM.*'
RETURN g.name
```

### Mostrar los grupos con más administradores locales

```c
MATCH (g:Group) WITH g OPTIONAL
MATCH (g)-[r:AdminTo]->(c:Computer) WITH g,COUNT(c) as expAdmin
OPTIONAL MATCH (g)-[r:MemberOf*1..]->(a:Group)-[r2:AdminTo]->(c:Computer) WITH g,expAdmin,COUNT(DISTINCT(c)) as unrolledAdmin
RETURN g.name,expAdmin,unrolledAdmin, expAdmin + unrolledAdmin as totalAdmin
ORDER BY totalAdmin DESC
```

### Grupos que tienen Local Admin

```c
MATCH p=(m:Group)-[r:AdminTo]->(n:Computer)
RETURN m.name, n.name
ORDER BY m.name
```

### Grupo que este owned que tenga local admin

```c
MATCH (g:Group)-[:AdminTo]->(c:Computer)
WITH g
MATCH (g)<-[:MemberOf]-(u:User)
WHERE u.owned = true
RETURN g.name AS GroupName, COLLECT(u.name) AS OwnedUsers
```

### Grupos con permiso de RDP

```c
MATCH p=(m:Group)-[r:CanRDP]->(n:Computer)
RETURN m.name, n.name
ORDER BY m.name
```

### Grupos que pueden cambiar la pass

```c
MATCH p=(m:Group)-[r:ForceChangePassword]->(n:User)
RETURN m.name, n.name
ORDER BY m.name
```

### Encontrar qué grupos del dominio (excluyendo a los administradores del dominio y a los administradores de la empresa) son administradores de qué equipo

```c
MATCH (g:Group) WHERE NOT (g.name =~ '(?i)domain admins@.*' OR g.name =~ "(?i)enterprise admins@.*") OPTIONAL MATCH (g)-[:AdminTo]->(c1:Computer) OPTIONAL MATCH (g)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c2:Computer) WITH g, COLLECT(c1) + COLLECT(c2) AS tempVar UNWIND tempVar AS computers RETURN g.name AS GROUP, COLLECT(computers.name) AS AdminRights
```

### Encontrar qué grupos del dominio (excluyendo los grupos de alto privilegio marcados con AdminCount=true) son administradores de qué equipos

```c
MATCH (g:Group) WHERE g.admincount=false OPTIONAL MATCH (g)-[:AdminTo]->(c1:Computer) OPTIONAL MATCH (g)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c2:Computer) WITH g, COLLECT(c1) + COLLECT(c2) AS tempVar UNWIND tempVar AS computers RETURN g.name AS GROUP, COLLECT(computers.name) AS AdminRights
```

### Todos los permisos


```c
// Permisos para el grupo "Todos"
MATCH (g:Group {name: 'Everyone'})-[:HasSession|AdminTo|AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword]->(n)
RETURN n.name AS Nombre, labels(n) AS Etiquetas, g.name AS NombreGrupo

// Permisos para "Usuarios autenticados"
MATCH (g:Group {name: 'Authenticated Users'})-[:HasSession|AdminTo|AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword]->(n)
RETURN n.name AS Nombre, labels(n) AS Etiquetas, g.name AS NombreGrupo

// Permisos para "Usuarios del dominio"
MATCH (g:Group {name: 'Domain Users'})-[:HasSession|AdminTo|AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword]->(n)
RETURN n.name AS Nombre, labels(n) AS Etiquetas, g.name AS NombreGrupo

// Permisos para "Equipos del dominio"
MATCH (g:Group {name: 'Domain Computers'})-[:HasSession|AdminTo|AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword]->(n)
RETURN n.name AS Nombre, labels(n) AS Etiquetas, g.name AS NombreGrupo

```

## Computadora 

### Generar una lista de todos los sistemas operativos

```c
MATCH (c:Computer)
RETURN DISTINCT(c.operatingsystem)
```

### Obtener equipos con sistema operativo custom

```c
MATCH (c:Computer)
WHERE c.operatingsystem CONTAINS "Windows 7"
RETURN c.name, c.operatingsystem
```

### Encontrar todas las computadoras con sesiones de usuarios de un dominio diferente (buscando oportunidades de compromiso entre dominios).

```c
MATCH (u:User)-[:HasSession]->(c:Computer)
WHERE NOT u.domain = c.domain
RETURN u.name, u.domain, c.name, c.domain
```

### Buscar cualquier computadora que NO sea un controlador de dominio en el que se confíe para realizar una delegación unconstrained.

```c
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group)
WHERE g.objectsid ENDS WITH "-516" WITH COLLECT(c1.name) AS domainControllers
MATCH (c2:Computer {unconstraineddelegation:true})
WHERE NOT c2.name IN domainControllers RETURN c2.name,c2.operatingsystem
ORDER BY c2.name ASC
```

### Encontrar todas las instancias de una cuenta de computadora que tenga derechos de administrador local en otras computadoras.

```c
MATCH (machine:Computer)-[:AdminTo]->(target:Computer)
WHERE machine.objectid IS NOT NULL
RETURN machine.name, COLLECT(target.name) AS AdminRightsOn, COUNT(target) AS NumberOfMachines
ORDER BY NumberOfMachines DESC

```

### Encontrar computadoras con descripciones y mostrarlas

```c
MATCH (c:Computer)
WHERE c.description IS NOT NULL
RETURN c.name,c.description
```

### Mostrar los equipos (excluyendo los controladores de dominio) en los que los administradores de dominio han iniciado sesión: 

```c
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name: "DOMAIN ADMINS@DOMINIO.COM"})
WHERE NOT c:DomainController
RETURN c.name AS ComputerName, collect(u.name) AS DomainAdminsLoggedIn
```

### Encontrar en cada equipo quién puede RDP (buscando sólo los usuarios habilitados):   

```c
MATCH (c:Computer) OPTIONAL
MATCH (u:User)-[:CanRDP]->(c)
WHERE u.enabled=true OPTIONAL
MATCH (u1:User)-[:MemberOf*1..]->(:Group)-[:CanRDP]->(c)
where u1.enabled=true
WITH COLLECT(u) + COLLECT(u1) as tempVar,c UNWIND tempVar as users
RETURN c.name AS COMPUTER,COLLECT(DISTINCT(users.name)) as USERS
ORDER BY USERS desc
```

### Users owned que pueden RDP

```c
MATCH (u:User)-[:CanRDP]->(c:Computer)
WHERE u.enabled = TRUE AND u.owned = TRUE
RETURN c.name AS ComputerName, COLLECT(u.name) AS OwnedUsersWithRDP
```

### Numero de equipos en los que el usuario tiene administrador local

```c
MATCH (u:User)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c:Computer)
RETURN count(DISTINCT(c.name)) AS COMPUTER, u.name AS USER ORDER BY u.name
```

### Mostrar los nombres de los equipos en los que cada usuario del dominio tiene privilegios de administrador derivados

```c
MATCH (u:User)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c:Computer)
RETURN DISTINCT(c.name) AS COMPUTER, u.name AS USER ORDER BY u.name
```

### Conteo de equipos que no tienen admin locales

```c
MATCH (n)-[r:AdminTo]->(c:Computer) WITH COLLECT(c.name) as compsWithAdmins
MATCH (c2:Computer) WHERE NOT c2.name in compsWithAdmins
RETURN COUNT(c2)
```

### Nombres de equipos que no tienen admin locales

```c
MATCH (c:Computer)
WHERE NOT (c)<-[:AdminTo]-(:User) AND NOT (c)<-[:AdminTo]-(:Group)
RETURN c.name AS ComputerWithoutLocalAdmins
```


## Dominio


