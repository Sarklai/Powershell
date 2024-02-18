$var = "LOCATION"

$env:HostIP = (
    Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -ne "Disconnected"
    }
).IPv4Address.IPAddress

$location = "PUL"

130..142 | foreach {if ($env:HostIP  -like "10.53.$_.*"){$location = "VIT"} }

194..208 | foreach {if ($env:HostIP  -like "10.52.$_.*"){$location = "PUL"} }

193..204 | foreach {if ($env:HostIP  -like "10.56.$_.*"){$location = "AER"} }

66..87 | foreach {if ($env:HostIP  -like "10.53.$_.*"){$location = "POL"} }

2..29 | foreach {if ($env:HostIP  -like "10.53.$_.*"){$location = "OKT"} }

130..142 | foreach {if ($env:HostIP  -like "10.52.$_.*"){$location = "LAH"} }

[System.Environment]::SetEnvironmentVariable($var,$location,[System.EnvironmentVariableTarget]::User)