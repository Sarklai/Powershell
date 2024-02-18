$ErrorActionPreference = 'SilentlyContinue'

Write-Host "<<<-------------------------------------------------------"  -ForegroundColor green
Write-Host "Скрипт определяет залогиненого на компьютере пользователя.`nЗАКРЫТЬ ПРОГРАММУ: CTRL+C" -ForegroundColor green
Write-Host "------------------------------------------------------->>>`n"  -ForegroundColor green

function Main {
                $PcName = $null
                $PcName = read-host -Prompt "Введите имя компьютера"
                $test = get-adcomputer $PcName
                    if ($test) {
                                 $login = Invoke-Command -ComputerName $PcName -ScriptBlock {(Get-wmiobject win32_computerSystem).Username}
                                 $login = $login -replace "ROLFNET."
                                 $name = Get-ADUser -Identity $login -Properties * | select -ExpandProperty name
                                 $title = Get-ADUser -Identity $login -Properties * | select -ExpandProperty title
                                 $Department = Get-ADUser -Identity $login -Properties * | select -ExpandProperty Department
                                 Write-host "`n$PcName | $login | $name | $title`n"
                                 Write-Host "------------------------------------------------------->>>`n"  -ForegroundColor green
                                 Main
                             }else{
                                    Write-host "Компьютер не найден" -ForegroundColor red; Main
                                    }
        

                }

Main