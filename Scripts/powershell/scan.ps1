]param (
    [string[]]$CIDRs = @("192.168.1.0/24", "10.0.0.0/24"), 
    [int[]]$Ports = @(21, 22, 23, 25, 53, 80, 110, 139, 443, 445),
    [string]$OutputFile = "scan_results.csv"
)

function Get-IPRange {
    param ($CIDR)
    $ip, $prefix = $CIDR -split "/"
    $prefix = [int]$prefix
    $ipBytes = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
    $mask = -bnot ([Math]::Pow(2, 32 - $prefix) - 1)
    $start = $ipInt -band $mask
    $end = $start + ([Math]::Pow(2, 32 - $prefix) - 1)

    $ips = @()
    for ($i = $start; $i -le $end; $i++) {
        $bytes = [BitConverter]::GetBytes($i)
        [Array]::Reverse($bytes)
        $ips += [System.Net.IPAddress]::new($bytes)
    }
    return $ips
}

function Scan-Port {
    param ($IP, $Port)
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($IP, $Port, $null, $null)
        $success = $asyncResult.AsyncWaitHandle.WaitOne(500, $false) # Timeout de 500ms
        if ($success) {
            $tcpClient.EndConnect($asyncResult)
            $tcpClient.Close()
            return "Open"
        } else {
            return "Closed"
        }
    } catch {
        return "Closed"
    }
}

$results = @()

foreach ($cidr in $CIDRs) {
    Write-Host "⏳ Escaneando CIDR: $cidr..." -ForegroundColor Cyan
    $ips = Get-IPRange -CIDR $cidr
    foreach ($ip in $ips) {
        foreach ($port in $Ports) {
            Write-Host "🔍 Escaneando $ip : $port ..." -NoNewline
            $status = Scan-Port -IP $ip -Port $port
            if ($status -eq "Open") {
                Write-Host " ✅ Abierto" -ForegroundColor Green
            } else {
                Write-Host " ❌ Cerrado" -ForegroundColor Red
            }
            $results += [PSCustomObject]@{
                IP = $ip
                Port = $port
                Status = $status
            }
        }
    }
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation
Write-Host "`n✅ Escaneo completado. Resultados guardados en $OutputFile" -ForegroundColor Yellow
