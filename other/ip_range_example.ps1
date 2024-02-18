[array]$ips = 1..254 | ForEach-Object -Process {'192.168.1.' + $_ , '192.168.10.' + $_}
write-host $ips