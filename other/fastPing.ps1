#$computers = Get-ADComputer -SearchBase 'OU=OU-CarLine,OU=OU-Piter,DC=int,DC=rolfcorp,DC=ru' -Filter * | select -ExpandProperty name
$computers = Get-Adcomputer -filter {Name -like "CL-KASSA*"} | select -expandproperty name
foreach ($computer in $computers)
{
    if (Test-Connection $computer -Quiet -Count 1)
    {
        Write-host ('Комп: {0} отвечает' -f $computer) -ForegroundColor Green
    }
    else
    {
        Write-host ('Комп {0} не отвечает' -f $computer) -ForegroundColor Red
    }
}