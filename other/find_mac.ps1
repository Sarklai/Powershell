Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'" -ComputerName cl-kassa-04
Get-WmiObject win32_Networkadapter -Filter "netenabled = 'true'" -ComputerName cl-kassa-04