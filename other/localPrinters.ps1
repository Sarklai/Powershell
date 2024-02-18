$localPrinters = get-printer | sort-object name | where-object -filter {$_.Type -eq "Connection"} | select -expandproperty name
foreach ($p in $localPrinters){ $p -replace "..\w*-\w*-\d\d.","" }