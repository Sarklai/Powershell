$token = "XXXXXXXXX:token_token_token_token_token" #Токен бота
$chat_id = "-XXXXXXXXXX" #ИД чата
$masternick = "tg_username" #ТГ юзернейм для расширенного функционала

#Данные для работы с OMNITRACKER
$strServerName = "srvHostname" 
$strServerPort = 5085
$strLoginName = "login"
$strPassWd = "password"


# API функции


# Отправить текстовое сообщение
function SendMessage($chatID, $text)
{
    $url = "https://api.telegram.org/bot$token/sendMessage"
    $params = @{
                    chat_id = $chatID
                    text = $text
                    parse_mode = "Markdown"
                }

    $response = Invoke-RestMethod -Uri $url -Method POST -Body $params
    return $response.result.message_id
}


# Отредактировать отправленное сообщение по ID
function EditMessage($chatID, $messageID, $text)
{
    $url = "https://api.telegram.org/bot$token/editMessageText"
    $params = @{
                    chat_id = $chatID
                    message_id = $messageID
                    text = $text
                    parse_mode = "Markdown"
                }

    Invoke-RestMethod -Uri $url -Method POST -Body $params | Out-Null
}


# Проверить существует сообщение или нет
function CheckMessageExistence($chatID, $messageID)
{
    $url = "https://api.telegram.org/bot$token/getUpdates"
    $response = Invoke-RestMethod -Uri $url -Method GET
    
    foreach ($update in $response.result)
    {
        if ($update.message.message_id -eq $messageID -and $update.message.chat.id -eq $chatID)
        {
            return $true
        }
    }
    
    return $false
}


# Отправить локальный файл
function SendFile {
    param(
        [string]$chatID,
        [string]$file,
        [string]$description
    )

    $Uri = "https://api.telegram.org/bot$($token)/sendDocument"
    $Form = @{
        chat_id = $chatID
        document = Get-Item $file
        caption = $description
        ParseMode = 'MarkdownV2'
    }

    Invoke-RestMethod -Uri $Uri -Form $Form -Method Post | Out-Null

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


# Отправка аудиофайла
function SendTGAudio
{
    param(
        [string]$chatID,
        [string]$audio,
        [string]$description
    )

    $Uri = "https://api.telegram.org/bot$($token)/sendAudio"

    $audioInfo = Get-Item $audio
    $audioDuration = [System.Media.SoundPlayer]::fromfile($audio).duration / 1000  # Calculate duration in seconds

    $Form = @{
        chat_id = $chatID
        audio = $audioInfo
        caption = $description
        duration = $audioDuration
        ParseMode = 'MarkdownV2'
    }

    Invoke-RestMethod -Uri $Uri -Form $Form -Method Post
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




WRITE-HOST "

  ___  ____               ______     ____   _________ 
 |_  ||_  _|             |_   _ \  .'    \.|  _   _  |
   | |_/ /      ______     | |_) |/  .--.  \_/ | | \_|
   |  __'.     |______|    |  __/.| |    | |   | |    
  _| |  \ \_              _| |__) |  \--'  /  _| |_   
 |____||____|            |_______/ \.____.'  |_____|  

"


$latestID = 0
$updates = GetUpdates($latestID)

if ($updates -ne $null)
{
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
                $output = "$username - $text"
                Add-Content -Path "$PSScriptRoot\LOG\ADM_LOG_$(Get-Date -Format 'yyyyMMdd').txt" -Value $output  #Пишет логи запросов в файлик
                
            
            # Разблокировать учетку
            if ($text -match "UL (.*)")
            {
                if ($username -eq $masternick)
                {
                    $accountName = $matches[1]
                    Unlock-ADAccount $accountName
                    SendMessage $chatID "УЗ $accountName разблокирована"
                }
                    
            }


            # Сброс пароля на стандартный
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
                    SendMessage $chatID "Найдено слишком много совпадений, просьба сформулировать более точный запрос"
                }
                else
                {
                    foreach ($user in $userInfo)
                    {
                        $ou = $user.DistinguishedName -split ',' | Where { $_ -match 'OU=' } | ForEach-Object { $_ -replace 'OU=', '' }
                        $info = "ФИО: $($user.Name) `n" 
                        $info += "Login: $($user.SamAccountName)`n"
                        $info += "Табельный: $(if($user.extensionAttribute14) {$user.extensionAttribute14} else { '-' })`n"
                        $info += "Незалочена: $($user.LockedOut -replace 'True', '❌' -replace 'False', '✅')`n"
                        $info += "Пароль УЗ: $($user.PasswordExpired -replace 'True', '❌' -replace 'False', '✅')`n"
                        $info += "Активная: $($user.Enabled -replace 'True', '✅' -replace 'False', '❌')`n"
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
                                SendLocalPhoto $chatID $imagePath $info
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
            if ($text -match "PCINFO (.*)")
            {
                $compN = $matches[1]
                Add-Content -Path "$PSScriptRoot\LOG\ADM_LOG_$(Get-Date -Format 'yyyyMMdd').txt" -Value "INFO $compN " 
                  
                if ($compN -eq "127.0.0.1")
                {
                    SendMessage $chatID "Игнорирую пидарасов"
                }
                else
                {
                    if ($compN -as [System.Net.IPAddress])
                    {
                        $comp = [System.Net.Dns]::GetHostEntry($compN).HostName.split('.')[0]
                        if ($comp -like $null)
                        {
                            $comp = $compN
                        }
                }
                else
                {
                    $comp=$compN
                }

                write-host $comp $compN

                if (Get-ADComputer -Filter {Name -eq $comp})
                {
                    if (Test-Connection $comp -Quiet -Count 1)
                    {
                        $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $comp
                        $CS = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $comp
                        $BIOS_INF = Get-CimInstance -ClassName Win32_BIOS -ComputerName $comp
                        $processor = Get-CimInstance -ClassName Win32_Processor -ComputerName $comp
                        $motherboard = Get-CimInstance -ClassName Win32_BaseBoard -ComputerName $comp
                        $memory = Get-CimInstance -ClassName Win32_PhysicalMemory -ComputerName $comp
                        $disk = Get-CimInstance -ClassName Win32_DiskDrive -ComputerName $comp

                        $installDateFormatted = $os.InstallDate.ToString("dd/MM/yyyy")
                        $uptime = (Get-Date) - $OS.LastBootUpTime

                        $UN = ($CS.UserName) -replace '.*\\'

                        $network = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $comp | Where-Object {$_.IPEnabled -eq $true}
                        $IPv4Addresses = $network.IPAddress | Where-Object {$_ -like "*.*.*.*"}
                        $diskPartitions = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $comp | Where-Object {$_.DriveType -eq 3}

                        $PART = foreach ($partition in $diskPartitions)
                        {
                            $freeSpaceGB = "{0:F2}" -f ($partition.FreeSpace / 1GB)
                            $totalSpaceGB = "{0:F2}" -f ($partition.Size / 1GB)
                            $freeSpacePercentage = "{0:P2}" -f ($partition.FreeSpace / $partition.Size)
                            "$($partition.DeviceID) $freeSpaceGB GB ($freeSpacePercentage)"
                        }

                        switch ($memory.SMBIOSMemoryType)
                        {
                            26 { $MemoryType = "DDR4"; break }
                            24 { $MemoryType = "DDR3"; break }
                        }

                        switch ($memory.FormFactor)
                        {
                            12 { $FormFactor = "SODIMM"; break }
                            8 { $FormFactor = "DIMM"; break }
                        }

$systemInfo = @"
Комп: *$($CS.Name)*
Юзер: *$UN*

Проц: $($processor.Name)
Мать: $($motherboard.Product)
RAM: $FormFactor $MemoryType $(($memory | Measure-Object Capacity -Sum).Sum / 1GB) Gb | Slot(s): $(($memory | Select-Object -ExpandProperty BankLabel | Get-Unique).Count)
Disk: $($disk | Select-Object -ExpandProperty Model)
SN: *$($BIOS_INF.SerialNumber)*

OS: $($os.Caption) *$($os.BuildNumber)* | Installed: $installDateFormatted
Free: $PART
MAC: $($network.MACAddress)
IP: $($IPv4Addresses -join ', ')
UPtime: $($uptime.Days) D $($uptime.Hours) h $($uptime.Minutes) min
"@

                        $Lines = @(query user /server:$comp) -split "\n"

                        if ($Lines -eq $Null)
                        {
                            $seancess = "Нет активных сеансов"
                        }
                        else
                        {

                            foreach($Line in $Lines)
                            {
                                if (($Line -match "USERNAME\s+SESSIONNAME\s+ID\s+STATE\s+IDLE TIME\s+LOGON TIME") -or ($Line -match "ПОЛЬЗОВАТЕЛЬ\s+СЕАНС\s+ID\s+СТАТУС\s+БЕЗДЕЙСТВ`.\s+ВРЕМЯ ВХОДА"))
                                {
                                    continue  # Игнорируем строку с заголовками
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
                            
                                $seancess += "Логин: *$($username.ToUpper())* | ID: $remoteSessionID | Статус: *$($status)*`n"

                             }

                            }


                        $mID = SendMessage $chatID $systemInfo
                        $systemInfo=""

                        $res = Invoke-Command –ComputerName $($CS.Name) –ScriptBlock {

                        $diskinfo = @()
                        $Mon = @()
                        $MonINFO = @()

                        $storage = Get-PhysicalDisk 
                        foreach ($disk in $storage)
                        {
                            $storageType = $disk.MediaType
                            $diskSize = [math]::Round(($disk.Size / 1GB), 2)
                            $diskinfo += "$storageType $diskSize GB"
                        }

                        $devices = Get-PnpDevice | Where-Object {$_.Status -eq 'OK' -and $_.Class -eq 'Monitor'}
                        foreach ($device in $devices)
                        {
                            $deviceId = $device.InstanceId
                            $monitor = "HKLM:\SYSTEM\CurrentControlSet\Enum\$deviceId"
                            $monitorIdSubkey = Join-Path -Path $monitor -ChildPath 'Device Parameters'

                            if (Test-Path -Path $monitorIdSubkey)
                            {
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
                                        $monserialNumber ="-"
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
               
                                    if ($Model -like $null)
                                    {
                                        $Model ="Нет подключенного монитора"
                                    }

                                    $Mon += $Model
                                }
                            }
                        }
    

                        [PSCustomObject]@{
                            Monitor = $Mon -join ", "
                            MonInfo = $MonINFO -join ", "
                            StorageType = $diskinfo -join ", "
                            }
                        }
   

$systemInfo = @"
Комп: *$($CS.Name)*
Юзер: *$UN *

Сеансы:
$seancess
Проц: $($processor.Name)
Мать: $($motherboard.Product)
RAM: $FormFactor $MemoryType $(($memory | Measure-Object Capacity -Sum).Sum / 1GB) Gb | Slot(s): $(($memory | Select-Object -ExpandProperty BankLabel | Get-Unique).Count)
Disk(s): $($res.StorageType)
Additional Info: $($disk | Select-Object -ExpandProperty Model)
Monitor: $($res.Monitor)
Моник-Инфо: $($res.MonInfo)
SN: *$($BIOS_INF.SerialNumber)*

OS: $($os.Caption)* $($os.BuildNumber)* | Installed: $installDateFormatted
Free Space: $PART
MAC: $($network.MACAddress)
IP: $($IPv4Addresses -join ', ')
UPtime: $($uptime.Days) D $($uptime.Hours) h $($uptime.Minutes) min


"@

                        EditMessage $chatID $mID $systemInfo
                        $res = $null
                        $systemInfo = $null

                    }
                    else
                    {
                        SendMessage $chatID "$comp не PING"}
                    }
                    else
                    {
                        SendMessage $chatID "Устройство $compN не входит в AD или DHCP не вернул имя"}
                    }

      		    #Очищает переменные ВАЖНО.
                    Clear-variable seancess, username, remoteSessionID, date, time, comp, status, $comp, $systemInfo, $res

                }

        
            # ЛАПС (Узнать пароль локального админа на конкретном ПК)
            if ($text -match "^(LAPS) (.*)$")
            {
                $compname = $matches[2]
                $computer = Get-ADComputer -Filter {Name -eq $compname}
                Add-Content -Path "$PSScriptRoot\LOG\ADM_LOG_$(Get-Date -Format 'yyyyMMdd').txt" -Value "$compname" 
                if ($computer)
                {
                    $Pass = Get-ADComputer -Identity $compname -Properties ms-mcs-admpwd | Select-Object -ExpandProperty ms-mcs-admpwd

   	   	    # Синтезатор голоса записывает аудио, на случай если пароль сгенерировался не читабельным
                    if ($Pass -ne $null)
                    {
                        $synthesizer = New-Object System.Speech.Synthesis.SpeechSynthesizer
                        $synthesizer.Rate = -3 
                        $audio = "$PSScriptRoot\pass.wav"
                        $synthesizer.SetOutputToWaveFile($audio)
                        $P_ASS = $Pass -split "(?!^)"
                        $P_ASS =  $P_ASS -join " "
                        $synthesizer.Speak($P_ASS)
                        $synthesizer.SetOutputToDefaultAudioDevice()

                        SendFILE $chatID $audio $Pass

                        Remove-Item -Path $audio
                        $Pass = ""
                    }
                    else
                    {
                        SendMessage $chatID "Нет пароля для $compname `nПробуй стандартный`nУдачи =)"
                    }
                }
                else
                {
                    SendMessage $chatID "$compname не найден в АД `nУ тебя есть два пути:`n1. Перезалить Windows;`n2. Изменить пароль локального админа с помощью: https://www.hirensbootcd.org/`n`nУдачи =)"
                }
            }


             #Узнать свободное имя для компуктера
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


             #Узнать активные сессии на комуктере
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


      	     #Проверить ссылку на VirusTotal
             if ($text -match "^(CHECKURL|ЧЕКУРЛ) (.*)$")
             {
                    $testUrl = $matches[2]
                    $headers=@{}
                    $headers.Add("accept", "application/json")
                    $headers.Add("x-apikey", "3d22378329d8e185644c0222321403f7e6067c498db5e5d52d2515dcd7630fa1")
                    $headers.Add("content-type", "application/x-www-form-urlencoded")
                    $response = Invoke-WebRequest -Uri 'https://www.virustotal.com/api/v3/urls' -Method POST -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body "url=$testUrl"


                    $pattern = '"id": "(.*?)",'
                    $matches = [regex]::Match($response.Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

                    if ($matches.Success)
                    {
                        $analysisID = $matches.Groups[1].Value
                        $analysisID

                        DO
                        {
                            $response = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/analyses/$analysisID" -Method GET -Headers $headers
                            $response.Content
                            $pattern = '"status": (.*?),'
                            $matches = [regex]::Match($response.Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
                            $status = $matches.Groups[1].Value
                        }
                        Until
                        ($status -eq "`"completed`"")

                        Clear-Variable matches, pattern


                        $pattern = '"malicious": (.*?),'
                        $matches = [regex]::Match($response.Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
                        $malicious = $matches.Groups[1].Value

                        $pattern = '"suspicious": (.*?),'
                        $matches = [regex]::Match($response.Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
                        $suspicious = $matches.Groups[1].Value

                        $pattern = '"undetected": (.*?),'
                        $matches = [regex]::Match($response.Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
                        $undetected = $matches.Groups[1].Value

                        $pattern = '"harmless": (.*?),'
                        $matches = [regex]::Match($response.Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
                        $harmless = $matches.Groups[1].Value


                        $testResult = "В результате проверки множеством сервисов VirusTotal, были получены следующие результаты:`n`nВредоносно: $malicious`nПодозрительно: $suspicious`nНе обнаружено: $undetected`nБезвредно: $harmless`n`n"

                        sendMessage $chatID $testResult
                    }
                    else
                    {
                        sendMessage $chatID "Не удалось проверить ссылку: `"$testUrl`""
                    }
             }


             #Список почтовых групп конкретного пользователя
             if ($text -match "^(mailgroups) (.*)")
             {
                $user = $matches[2]
                write-host $user
                $userInfo = Get-ADUser -Filter {SamAccountName -eq $user} -Properties *

                if (-not $userinfo)
                {
                    SendMessage $chatID "Никого не нашел"
                }
                else
                {
                    $groupList = get-ADPrincipalGroupMembership $user | Where-Object {$_.name -match "#\w+"} | select -ExpandProperty name
                    $groupList = $groupList -join "`n"
                    SendMessage $chatID "Список почтовых рассылок $($user):`n$groupList"
                }

                Clear-Variable user, groupList
             }



             #Список групп безопасности конкретного пользователя
	     ###ПОФИКСИТЬ: У половины пользователей есть баг, при котором api сервер возвращает 400 ошибку и не передает результат в чат, пока причина не выявлена.
             if ($text -match "^(usergroups) (.*)")
             {
                $user = $matches[2]
                write-host $user
                $userInfo = Get-ADUser -Filter {SamAccountName -eq $user} -Properties *

                if (-not $userinfo)
                {
                    SendMessage $chatID "Никого не нашел"
                }
                else
                {
                    $groupList = get-ADPrincipalGroupMembership $user | Where-Object {$_.name -notmatch "#\w+"} | select -ExpandProperty name
                    $groupList = $groupList -join "`n"
                    SendMessage $chatID "Список групп безопасности $($user):`n$groupList"
                }

                Clear-Variable user, groupList
             }


	     #Список доступных команд
             if (($text -eq 'инфо') -or ($text -eq 'info'))
             {
$info = "
Командлист:`n
1. Поиск информации о сотруднике:
```ХУИЗ|WHOIS [Логин] или [ФИО]``` `n
2. Сбор информации о компьютере:
```PCINFO [Имя компьютера]``` `n
3. Информация по заявке в ОМНИ:
```ОМНИ|OMNI [Номер заявки]``` `n
4. Узнать пароль локального админа:
```LAPS [Имя компьютера]``` `n
5. Узнать свободное имя для компьютера:
```NAME [Имя компьютера без цифры*]``` `n
6. Информация по сеансам на компьютере:
```SESSIONS [Имя компьютера]``` `n
7. Получить список рассылок сотрудника:
```MAILGROUPS [Логин]``` `n
8. Получить список групп сотрудника:
```USERGROUPS [Логин]``` `n
"

                SendMessage $chatID $info
             }


            }

        }
    }

    Start-Sleep -Seconds 2
}
