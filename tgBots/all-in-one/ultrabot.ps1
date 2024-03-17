[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$token = "Токен бота"
$chatID = "Чат ИД"


# API функции

# Отправить текстовое сообщение
function SendMessage
{
    param(
        [string]$chatID,
        [string]$text
    )

    $url = "https://api.telegram.org/bot$token/sendMessage"

    $Body = @{
        chat_id = $chatID
        text = $text
    }
    Invoke-RestMethod -Uri $url -Method POST -Body $Body | Out-Null
}


# Отправить локальный файл
function SendLocalFile
{
    param(
        [string]$chatID,
        [string]$file,
        [string]$description
    )

    $Uri = "https://api.telegram.org/bot$($token)/sendDocument"

    # Build the Form
    $Form = @{
        chat_id = $chatID
        document = Get-Item $file
        caption = $description
    }

    Invoke-RestMethod -Uri $Uri -Form $Form -Method Post
}


# Отправить локальное изображение
function SendLocalPhoto
{
    param(
        [string]$chatID,
        [string]$photo,
        [string]$description
    )

    $Uri = "https://api.telegram.org/bot$($token)/sendPhoto"

    # Build the Form
    $Form = @{
        chat_id = $chatID
        photo = Get-Item $photo
        caption = $description
    }

    Invoke-RestMethod -Uri $Uri -Form $Form -Method Post
}


# Отправить изображение глобальной ссылкой
function sendUrlPhoto($chat_id, $photoUrl)
{
    $photoUrl = [System.Web.HttpUtility]::UrlEncode($photo_url)

    $url = "https://api.telegram.org/bot$token/sendPhoto?chat_id=$chat_id&photo=$photo_url"

    Invoke-RestMethod -Uri $url
}


# Проверить изменения в чате
function GetUpdates($offset)
{
    $url = "https://api.telegram.org/bot$token/getUpdates"
    $params = @{
        offset = $offset
    }
    $response = Invoke-RestMethod -Uri $url -Method GET -Body $params
    return $response.result
}

$latestID = 0
$updates = GetUpdates($latestID)

if ($updates -ne $null) {
    $latestID = $updates[-1].update_id + 1
}

# - Цикл -

while ($true) 
{
    $updates = GetUpdates($latestID)

    if ($updates -ne $null)
    {
        foreach ($update in $updates)
        {
            $latestID = $update.update_id + 1
            $message = $update.message
            $chat = $message.chat
            $chatID = $chat.id
            $text = $message.text
            $from = $message.from
            $username = $from.username

            if ($chatID -eq $chat_id)
            {
                Write-Host "$username - $text"
                
            }


            #Разблокировать учетку
            if ($text -match "UL (.*)")
            {
                if ($username -eq $masternick)
                {
                    $accountName = $matches[1]
                    Unlock-ADAccount $accountName
                    SendMessage $chatID "УЗ $accountName разблокирована"
                }
                    
            }


            #Сброс пароля на стандартный
            if ($text -match "SP (.*)")
            {
                if ($username -eq $masternick)
                {
                    $accountName =$matches[1]
                    $newPassword = ConvertTo-SecureString -String "Aa12345" -AsPlainText -Force
                    Set-ADAccountPassword -Identity $accountName -NewPassword $newPassword -PassThru | Set-ADUser
                    Unlock-ADAccount -Identity $accountName
                    Set-ADUser -Identity $accountName -ChangePasswordAtLogon $true
                    SendMessage $chatID "Пароль $accountName сброшен на стандартный"
                 }
             }


             # Получить информацию по сотруднику
             if ($text -match "^(хуиз|whois) (.*)$")
             {
                $accountName = $matches[2]
                $Name = "$accountName*"
                $userInfo = Get-ADUser -Filter "DisplayName -like '$Name' -or SamAccountName -eq '$accountName'" -Properties Name, SamAccountName, Company, Title, Department, MobilePhone, HomePhone, DistinguishedName, PasswordExpired, LockedOut, Enabled, extensionAttribute14
                if (-not $userInfo)
                {
                    SendMessage $chatID "Никого не нашел"
                }
                elseif ($userInfo.Count -gt 7)
                {
                    SendMessage $chatID "Зашкаливает, давай конкретнее `n !!Больше 7 записей!!"
                }
                else
                {
                    foreach ($user in $userInfo)
                    {
                        $ou = $user.DistinguishedName -split ',' | Where { $_ -match 'OU=' } | ForEach-Object { $_ -replace 'OU=', '' }
                        $info = "ФИО: $($user.Name) `n" 
                        $info += "Login: $($user.SamAccountName)`n"
                        $info += "Табельный: $(if($user.extensionAttribute14) {$user.extensionAttribute14} else { '-' })`n"
                        $info += "Заблокирована: $($user.LockedOut)`n"
                        $info += "Пароль истек: $($user.PasswordExpired)`n"
                        $info += "Включена: $($user.Enabled)`n"
                        $info += "Должность: $(if($user.Title) { $user.Title } else { '-' })`n"
                        $info += "Отдел: $(if($user.Department) { $user.Department } else { '-' })`n"
                        $info += "Организация: $(if($user.Company) { $user.Company } else { '-' })`n"
                        $info += "OU: $($ou -join ', ') `n"
                        $info += "Мобильный : $(if($user.MobilePhone) { $user.MobilePhone -replace '[^\d+]' } else { '-' })`n"
                        $info += "Внутренний: $(if($user.HomePhone) { $user.HomePhone } else { '-' }) `n" 
                        $ruk = ""

                        if ($($user.extensionAttribute14))
                        {
                            $USER_ID = $user.extensionAttribute14 -replace '\D', ''
                            $url = "https://myrolf/group/rolf/kartocki-pol-zovatelej/-/pc_cards/card/$USER_ID"
                            $username = 'rolfnet\laht-itsvc'
                            $password = '987532159'
                            $secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
                            $credential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
                            $response = Invoke-WebRequest -Uri $url -Credential $credential
        
                            $imageUrl = $response.Images.src
                            $imageUrl = $imageUrl -replace 'amp;', ''
        
                            $index = 4  
                            if ($imageUrl -and $imageUrl.Count -gt 4)
                            {
                                $fifthImageUrl = $imageUrl[$index]
                                $photo_URL="https://myrolf$fifthImageUrl"
                                $imagePath = "$PSScriptRoot\portal.jpg"
                                Invoke-WebRequest -Uri $photo_URL -Credential $credential -OutFile $imagePath
                                Write-Output $photo_URL
                             }

                             $pattern = '<h5>Мои руководители<\/h5>(.*?)<\/div> <\/div>'
                             $matches = [regex]::Match($response.Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

                             if ($matches.Success)
                             {
                                $desiredContent = $matches.Groups[1].Value
                                $subPattern = '<div class="appointmetn-pc-name"> <a href="https://myrolf/group/rolf/kartocki-pol-zovatelej/-/pc_cards/card/\d+">(.+?)</a> </div>'
                                $subMatches = [regex]::Matches($desiredContent, $subPattern)
    
                                if ($subMatches.Count -eq 0)
                                {
                                    $ruk = "Нет руководителей"
                                }
                                else
                                {
                                    $ruk = ''

                                    foreach ($match in $subMatches)
                                    {
                                        $ruk += $match.Groups[1].Value + "`n"
                                    }
                                 }
                              }
                              else
                              {
                                $ruk = "Нет раздела руководители"
                              }
                            }

                            $info += "Руководство: $ruk `n`n" 

                            if (Test-Path $imagePath)
                            {
                                Sendfile $chatID $imagePath $info
                                Remove-Item -Path $imagePath
                            }
                            else
                            {
                                SendMessage $chatID $info
                            }
                        }

                        $info=""
                    }

                               
            }


            # Получить информацию по заявкам из ОМНИ
            if ($text -match "^(OMNI|ОМНИ) (.*)$")
            {
                $ReqNum = $matches[2]
                if ($ReqNum -match '^\d+$' -and [int]$ReqNum -lt 10000000)
                {
                    $objOTApp = New-Object -ComObject OTAut.OtApplication
                    $objOTSession = $objOTApp.MakeSession($strServerName, $strServerPort, $strLoginName, $strPassWd)

                    if ($objOTSession -ne $null)
                    {
                        $ReqNum = $ReqNum.TrimStart('0')
                        WRITE-host "Searching request $ReqNum " -ForegroundColor White
                        $folderPath = "001 Деятельность"
                        $specificFolder = $objOTSession.GetRequestFolderByPath($folderPath)
    
                        if ($specificFolder -ne $null)
                        {
                            $filter = $specificFolder.MakeFilter()
                            $filter.UserField("Номер")=$ReqNum

                            $search = $specificFolder.CreateSearchRequest()
                            $search.Filter = $filter
                            $search.Recursive = $true
                            $result = $search.Execute()
                            if ($result -ne $null)
                            {
                                foreach ($req in $result)
                                {            
                                    $userFields = $req.UserFields
                                    $nm = $userFields.Item("Номер").Value
                                    $rabGrp = $userFields.Item("Рабочая группа").Value
                                    $status = $userFields.Item("Статус").Value
                                    $user = $userFields.Item("Пользователь").Value
                                    $priority = $userFields.Item("Приоритет").Value
                                    $description = $userFields.Item("Описание").Value
                                    $protocol = $userFields.Item("Протокол").Value
                                    $description | Out-File -FilePath 'description.txt'
                                    $protocol | Out-File -FilePath 'protokol.txt'
            
                                    write-host $nm $ReqNum
                                    if($nm -eq $ReqNum)
                                    {
                                        $file1 = 'description.txt' 
                                        SendFile  $chatID $file1 "Заявка:  $nm `nКоманда: $rabGrp `nСтатус: $status `nПользователь: $user"
                                        $file = 'protokol.txt'
                                        SendFile $chatID $file
                                        Remove-Item -Path "$PSScriptRoot\description.txt"
                                        Remove-Item -Path "$PSScriptRoot\protokol.txt"
                                     }
                                } 
                            }
                            else
                            {
                                SendMessage $chatID  "$ReqNum не найден."
                            }
                        }
                        else
                        {
                            SendMessage $chatID "Folder $folderPath not found."
                        }
 
                        # Close the session
                        $objOTSession.Logoff()
    
                    }
                    else
                    {
                        SendMessage $chatID  "Не смог создать сессию с $strServerName"
                    }                                 
                }
                else
                {    
                    SendMessage $chatID  "Ты по-моему перепутал"                   
                }
            }


            # Собрать информацию по компьютеру
            if ($text -like 'PCINFO*')
            {
                $comp = $($text) -replace "PCINFO ",""
                Write-Host $comp

                if (Test-Connection $comp -Quiet -Count 1)
                {
                    sendMessage $chatID "Нашел и опрашиваю $comp. Может занять пару минут... "
                    $res = Invoke-Command –ComputerName $comp –ScriptBlock {

                        $serialNumber = ""
                        $Mon = @()
                        $MonINFO = @()
                        $currentUser = ""
                        $processor = ""
                        $ramCapacity = ""
                        $storageType = ""
                        $diskinfo = @()
                        $lastBootTime = ""
                        $MG=""
                        $motherboard=""

                        $storage = Get-PhysicalDisk 
                        $diskinfo = @()

                        foreach ($disk in $storage)
                        {
                            $storageType = $disk.MediaType
                            $diskSize = [math]::Round(($disk.Size / 1GB), 2)
                            $diskinfo += "$storageType $diskSize GB"
                        }

                        $usedSpaceC = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "C:"} | Select-Object -ExpandProperty FreeSpace
                        $usedSpaceD = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "D:"} | Select-Object -ExpandProperty FreeSpace
                        $usedSpaceCInGB = [math]::Round($usedSpaceC / 1GB, 2)
                        $usedSpaceDInGB = [math]::Round($usedSpaceD / 1GB, 2)
            
                        # Мать
                        $motherboard = Get-WmiObject -Class Win32_BaseBoard | Select-Object -ExpandProperty Product

                        # аптайм
                        $lastBootTime = (Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)
                        $uptime = (Get-Date) - $lastBootTime
                        $uptimeFormatted = "{0} days, {1} hours, {2} minitus, {3} seconds" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds
            
                        # ОЗУ + слоты
                        $ram = Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum
                        $ramCapacity = [math]::Round($ram.Sum / 1GB, 2)
                        $ramSlotsUsed = Get-WmiObject -Class Win32_PhysicalMemory | Where-Object {$_.BankLabel -ne ""} | Measure-Object | Select-Object -ExpandProperty Count
            
                        # Получите серийный номер компьютера
                        $serialNumber = Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber
                        
                        $Mgeneration = Get-WmiObject Win32_PhysicalMemory | Select-Object SMBIOSMemoryType, FormFactor
          
                        if ($Mgeneration.SMBIOSMemoryType -eq 26)
                        {
                            $MemoryType = "DDR4"
                        }
                        elseif ($Mgeneration.SMBIOSMemoryType -eq 24)
                        {
                            $MemoryType = "DDR3"
                        }

                        if ($Mgeneration.FormFactor -eq 12)
                        {
                            $FormFactor = "SODIMM"
                        }
                        elseif ($Mgeneration.FormFactor -eq 8)
                        {
                            $FormFactor = "DIMM"
                        }
                        $MG= "$FormFactor $MemoryType"

                        # Получите имя текущего пользователя
                        $currentUser = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty UserName

                        # Получите модель процессора
                        $processor = Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name
                        $macAddress = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}).MacAddress -replace "-", ":"
                        $devices = Get-PnpDevice | Where-Object {$_.Status -eq 'OK' -and $_.Class -eq 'Monitor'}
                        $Mon = @()

                        foreach ($device in $devices)
                        {
                            $deviceId = $device.InstanceId
                            $monitor = "HKLM:\SYSTEM\CurrentControlSet\Enum\$deviceId"
                            $monitorIdSubkey = Join-Path -Path $monitor -ChildPath 'Device Parameters'

                            if (Test-Path -Path $monitorIdSubkey)
                            {
                                # Проверка наличия параметра EDID
                                if (Get-ItemProperty -Path $monitorIdSubkey -Name EDID -ErrorAction SilentlyContinue)
                                {
                                    $edidBytes = Get-ItemProperty -Path $monitorIdSubkey -Name EDID | Select-Object -ExpandProperty EDID
                                    $edidString = [System.BitConverter]::ToString($edidBytes)

                                    $startIndex = $edidString.IndexOf("00-00-00-FF-00-")
                                    if ($startIndex -ne -1)
                                    {
                                        $startIndex += 15
                                        $endIndex = $edidString.IndexOf("-0", $startIndex)
                                        if ($endIndex -ne -1)
                                        {
                                            $serialNumberHex = $edidString.Substring($startIndex, $endIndex - $startIndex).Replace("-", "")
                                            $monserialNumber = ""
                                            for ($i = 0; $i -lt $serialNumberHex.Length; $i += 2)
                                            {
                                                $hexByte = $serialNumberHex.Substring($i, 2)
                                                $asciiByte = [System.Convert]::ToByte($hexByte, 16)
                                                $monserialNumber += [System.Text.RegularExpressions.Regex]::Replace([System.Text.Encoding]::ASCII.GetString([byte[]]($asciiByte)), "[^\w\d]", "")
                                            }
                                        }
    
                                    }
                                    else
                                    {
                                        $monserialNumber = "-"
                                    }

                                        $MonINFO += $monserialNumber

                                        $startIndex1 = $edidString.IndexOf("00-00-00-FC-00-") + 15
                                        $endIndex1 = $edidString.IndexOf("-0", $startIndex1)
                                        $ModelHex1 = $edidString.Substring($startIndex1, $endIndex1 - $startIndex1).Replace("-", "")
                                        $Model = ""

                                        for ($i = 0; $i -lt $ModelHex1.Length; $i += 2)
                                        {
                                            $hexByte1 = $ModelHex1.Substring($i, 2)
                                            $asciiByte1 = [System.Convert]::ToByte($hexByte1, 16)
                                            $Model +=  [System.Text.RegularExpressions.Regex]::Replace([System.Text.Encoding]::ASCII.GetString([byte[]]($asciiByte1)), "[^\w\d ]", "")
                                        }

                                        $Mon += $Model
                                }
                            }
                        }

                        [PSCustomObject]@{
                            ComputerName = $env:COMPUTERNAME
                            SerialNumber = $serialNumber
                            Monitor = $Mon -join ", "
                            MonInfo = $MonINFO -join ", "
                            CurrentUser = $currentUser
                            Processor = $processor
                            RAMCapacity = "$ramCapacity GB"
                            StorageType = $diskinfo -join "`n"
                            RAMSlotsUsed = $ramSlotsUsed
                            MAC= $macAddress
                            LastBootTime = $uptimeFormatted
                            usedSpaceCInGB = $usedSpaceCInGB
                            usedSpaceDInGB = $usedSpaceDInGB
                            MG=$MG
                            MB = $motherboard
                        }
                    }

                    if ($res.CurrentUser -like $null)
                    {
                        $res.CurrentUser = "_Нет активных сессий_"
                    }
                    if ($res.Monitor -like $null)
                    {
                        $res.Monitor = "Дисплей не подключен"
                    }
                    if ($res.MonInfo -like $null)
                    {
                        $res.MonInfo = "-"
                    }
                    if ($res.ComputerName -like $null)
                    {
                        $photoUrl = "https://citaty.info/files/portraits/screenshot_8_16.jpg"
                        sendURLPhoto $chatID $photo_url
                    }
                    else
                    {
                        sendMessage $chatID "Комп:  $($res.ComputerName) `nЮзер:  $($res.CurrentUser) `nПроц: $($res.Processor)`nМать: $($res.MB)`nRAM: $($res.RAMCapacity) | Type: $($res.MG) | Slot(s): $($res.RAMSlotsUsed)`nДиск(и): $($res.StorageType)`nFreeSpace: C: $($res.usedSpaceCInGB)Gb | D: $($res.usedSpaceDInGB)Gb `nSN: $($res.Serialnumber) `nМонитор(ы): $($res.Monitor)`nМоник-Инфо: $($res.Moninfo)`nMAC: $($res.MAC)`nUPtime: $($res.LastBootTime)  "
                    }

                    $comp = $null
                }
                else 
                {
                    sendMessage $chatID "$comp не PING :("
                    $comp = $null
                }

            }


            # ЛАПС
            if($text -like 'LAPS*')
            {
                $comp = $($text) -replace "LAPS ",""
                $compCheck = get-adcomputer $comp

                if ($compCheck -eq $Null)
                {
                    sendMessage $chatID "Такого компьютера нет в АД`nУ тебя есть два пути:`n1. Перезалить Windows;`n2. Изменить пароль локального админа с помощью: https://www.hirensbootcd.org/`n`nУдачи =)"
                    $comp = $null
                }
                else
                {
                    $password = get-adcomputer $comp -properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd
                    $compCheck = $null
                    $comp = $null
                    if ($password -eq $null)
                    {
                    sendMessage $chatID "У этого компьютера нет LAPS,`nпопробуй стандартный пароль.`nЕсли не подойдёт пароль, то для тебя есть два варианта:`n1. Перезалить Windows;`n2. Изменить пароль локального админа с помощью: https://www.hirensbootcd.org/`n`nУдачи =)"
                    $comp = $null
                    }
                    else
                    {
                    sendMessage $chatID  "$password"
                    $comp = $null
                    }
                }

                $password = $Null
             }



             if($text -like 'NAME*')
             {
               $pcname = $($text) -replace "NAME ",""
               $i = 0
               $b = 1
               $a = $null
               While ($i -eq 0)
               {
                  if ($b -lt 10)
                  {
                       $a = "$($pcname)0$($b)"
                   }
                   else
                   {
                       $a = "$($pcname)$b"
                   }

                   $Check = get-adcomputer $a | select -ExpandProperty name

                   if  ($Check -eq $a)
                   {
                       $b++
                       $a = $null
                   }
                   else
                   {
                       sendMessage $chatID  "Свободное имя $a"
                       $b = 1
                       $i = 1
                       $a = $null
                    }
                }
             }



             if ($text -like 'Sessions*')
             {
                $comp = $($text) -replace "Sessions ",""
            
                if (($comp -eq $env:computername) -or ($comp -eq "localhost") -or ($comp -eq "127.0.0.1"))
                    {
                        sendMessage $chatID "$username - не лезь =)"
                    }
                    else
                        {
                            if (Test-Connection $comp -Quiet -Count 1)
                            {
                                $Lines = @(query user /server:$comp) -split "\n"

                                if ($Lines -eq $Null)
                                {
                                    sendMessage $chatID "*$($comp.ToUpper()):*`nНет активных сеансов"
                                }
                                else
                                    {

                                    foreach($Line in $Lines)
                                    {
                                        if (($Line -match "USERNAME\s+SESSIONNAME\s+ID\s+STATE\s+IDLE TIME\s+LOGON TIME") -or ($Line -match "ПОЛЬЗОВАТЕЛЬ\s+СЕАНС\s+ID\s+СТАТУС\s+БЕЗДЕЙСТВ`.\s+ВРЕМЯ ВХОДА"))
                                        {
                                            continue  # If is the header then skip to next item in array
                                        }

                                        $string = $Line -split "\s+"

                                        $username = $string[1]

                                        if($string[2] -match '\d+')
                                            {
                                                $remoteSessionID = $string[2]
                                                $date = $string[5]
                                                $time = $string[6]
                                                if (($string[3] -eq "active") -or ($string[3] -eq "активно"))
                                                    {
                                                        $status = "Активный"
                                                    }
                                                     else
                                                        {
                                                            $status = "-"
                                                        }
                                            }
                                            else
                                                {
                                                    $remoteSessionID = $string[3]
                                                    $date = $string[6]
                                                    $time = $string[7]
                                                    if (($string[4] -eq "active") -or ($string[4] -eq "активно"))
                                                        {
                                                            $status = "Активный"
                                                        }
                                                        else
                                                            {
                                                                $status = "-"
                                                            }
                                                }
                        
                                        $tgmsg += "Пользователь: $username`nID сессии: $remoteSessionID`nСтатус: $status`nДата и время авторизации:`n$date, $time`n`n"

                                    }
                                #$comp = $comp.ToUpper()
                                sendMessage $chatID "*$($comp.ToUpper()):*`n`n$tgmsg"

                                Clear-variable tgmsg
                                Clear-Variable username
                                Clear-Variable remoteSessionID
                                Clear-Variable date
                                Clear-Variable time
                                Clear-variable comp
                                Clear-variable status

                                }
                            }
                            else
                                {
                                    sendMessage $chatID "*$($comp.ToUpper()):*`n не PING :("
                                    Clear-variable comp
                                }
                        }
             }


        }
    }

    Start-Sleep -Seconds 2
}