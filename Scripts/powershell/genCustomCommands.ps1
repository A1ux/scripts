function Gen-CustomCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Archivo de entrada que contiene IPs o CIDRs")]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$File,

        [Parameter(Mandatory = $true, HelpMessage = "Comando personalizado con marcadores de posición IP")]
        [string]$Command,

        [string]$OutputFile,

        [switch]$Clipboard
    )

    # Leer el archivo con IPs o CIDRs y generar los comandos
    $ips = Get-Content $File

    # Almacenar los comandos generados
    $generatedCommands = @()

    foreach ($ip in $ips) {
        $nmap_command = $Command -replace "IP", $ip
        $generatedCommands += $nmap_command
    }

    if ($OutputFile) {
        # Escribir los comandos en el archivo de salida si se especifica
        $generatedCommands | Out-File -FilePath $OutputFile
        Write-Output "Se han generado los comandos en $OutputFile"
    } else {
        # Imprimir los comandos en pantalla si no se especifica archivo de salida
        $generatedCommands | ForEach-Object { Write-Output $_ }
    }

    # Si se especificó la opción de portapapeles, copiar los comandos al portapapeles
    if ($Clipboard) {
        $generatedCommands | Set-Clipboard
        Write-Output "Los comandos se han copiado al portapapeles."
    }
}