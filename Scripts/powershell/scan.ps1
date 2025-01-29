param (
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
        $tcpClient.Connect($IP, $Port)
        $tcpClient.Close()
        return "Open"
    } catch {
        return "Closed"
    }
}

$results = @()

foreach ($cidr in $CIDRs) {
    $ips = Get-IPRange -CIDR $cidr
    foreach ($ip in $ips) {
        foreach ($port in $Ports) {
            $status = Scan-Port -IP $ip -Port $port
            $results += [PSCustomObject]@{
                IP = $ip
                Port = $port
                Status = $status
            }
        }
    }
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation
Write-Host "Scan completed. Results saved in $OutputFile"
