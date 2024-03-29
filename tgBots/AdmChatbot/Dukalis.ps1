﻿$token = "XXXXXXXXX:token_token_token_token_token" #Токен бота
$timeout = 3
$chat_id = "-XXXXXXXXXX" #ИД чата
$i = 0
$photo = "https://ie.wampi.ru/2022/10/21/quickpicQR.jpg"
$URL_get = "https://api.telegram.org/bot$token/getUpdates"
$URL_set = "https://api.telegram.org/bot$token/sendMessage"
$URL_photo = "https://api.telegram.org/bot$token/sendPhoto"
$URL_document = "https://api.telegram.org/bot$token/sendDocment"

function getUpdates($URL)
{
    $json = Invoke-RestMethod -Uri $URL
    $data = $json.result | Select-Object -Last 1
    # Обнуляем переменные
    $text = $null
    $callback_data = $null

    # Обычное сообщение
    if($data.message)
    {
        $text = $data.message.text
        $f_name = $data.message.chat.first_name
        $l_name = $data.message.chat.last_name
        $username = $data.message.chat.username
    }
    
    $ht = @{}
    $ht["text"] = $text
    $ht["f_name"] = $f_name
    $ht["l_name"] = $l_name
    $ht["username"] = $username

    # confirm
    Invoke-RestMethod "$($URL)?offset=$($($data.update_id)+1)" -Method Get | Out-Null
    
    return $ht
}
<# Упрощенная отправка сообщений, отказался т.к. сам не до конца вдуплил API документацию, пока что юзаю вариант ниже, стащил со статьи HABR
function sendMessage($text)
{
    $chat_id = "-1001796872519"
    $text
    $URI = "https://api.telegram.org/bot" + $token + "/sendMessage?chat_id=" + $chat_id + "&text=" + $text

    Invoke-WebRequest -URI ($URI)
}#>

function sendMessage($URL, $chat_id, $text)
{
    # создаем HashTable, можно объявлять ее и таким способом
    $ht = @{
        text = $text
        parse_mode = "Markdown"
        chat_id = $chat_id
            }
    # В доке сказано что надо передавать данные в JSON.. ну ок.
    $json = $ht | ConvertTo-Json
    Invoke-RestMethod $URL -Method Post -ContentType 'application/json; charset=utf-8' -Body $json | Out-Null
}

function sendPhoto
{
    Invoke-Webrequest -Uri "https://api.telegram.org/bot$token/sendPhoto?chat_id=$chat_id&caption=Скачать QuickPic&photo=https://ie.wampi.ru/2022/10/21/quickpicQR.jpg" | Out-Null #Тестово, с внешнего адреса.
}

function sendDocument($URL, $chat_id, $documentObject)
{
    # создаем HashTable, можно объявлять ее и таким способом
    $ht = @{
        document = $documentObject
        parse_mode = "Markdown"
        chat_id = $chat_id
            }
    # Данные нужно отправлять в формате json
    $json = $ht | ConvertTo-Json
    Invoke-RestMethod $URL -Method Post -ContentType 'application/json; charset=utf-8' -Body $json | Out-Null
}

# ---------------- НАЧАЛО ----------------

while($true) # вечный цикл
{
    $return = getUpdates $URL_get





    if ($return.text -like 'PCINFO*') {
    $comp = $($return.text) -replace "PCINFO ",""
    Write-Host $comp
    if (Test-Connection $comp -Quiet -Count 1) {
    sendMessage $URL_set $chat_id "Нашел и опрашиваю $comp. Может занять пару минут... "
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
            $storage = Get-PhysicalDisk 
                 $diskinfo = @()
                 foreach ($disk in $storage) {
                    $storageType = $disk.MediaType
                    $diskSize = [math]::Round(($disk.Size / 1GB), 2)
                    $diskinfo += "$storageType $diskSize GB"
                    }
            $usedSpaceC = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "C:"} | Select-Object -ExpandProperty FreeSpace
            $usedSpaceD = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "D:"} | Select-Object -ExpandProperty FreeSpace
            $usedSpaceCInGB = [math]::Round($usedSpaceC / 1GB, 2)
            $usedSpaceDInGB = [math]::Round($usedSpaceD / 1GB, 2)


            # UPTIME
            $lastBootTime = (Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)
            $uptime = (Get-Date) - $lastBootTime
            $uptimeFormatted = "{0} days, {1} hours, {2} minitus, {3} seconds" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds
            
            #RAM SLOTS
            $ram = Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum
            $ramCapacity = [math]::Round($ram.Sum / 1GB, 2)
            $ramSlotsUsed = Get-WmiObject -Class Win32_PhysicalMemory | Where-Object {$_.BankLabel -ne ""} | Measure-Object | Select-Object -ExpandProperty Count
            
            # Получите серийный номер компьютера
            $serialNumber = Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber


            $Mgeneration = Get-WmiObject Win32_PhysicalMemory | Select-Object SMBIOSMemoryType, FormFactor
          
if ($Mgeneration.SMBIOSMemoryType -eq 26) {
    $MemoryType = "DDR4"
} elseif ($Mgeneration.SMBIOSMemoryType -eq 24) {
    $MemoryType = "DDR3"
}

if ($Mgeneration.FormFactor -eq 12) {
    $FormFactor = "SODIMM"
} elseif ($Mgeneration.FormFactor -eq 8) {
    $FormFactor = "DIMM"
}
$MG= "$FormFactor $MemoryType"



            # Получите имя текущего пользователя
            $currentUser = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty UserName

            # Получите модель процессора
            $processor = Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name
            $macAddress = (Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}).MacAddress
            $devices = Get-PnpDevice | Where-Object {$_.Status -eq 'OK' -and $_.Class -eq 'Monitor'}
            $Mon = @()
            foreach ($device in $devices) {
                $deviceId = $device.InstanceId
                $monitor = "HKLM:\SYSTEM\CurrentControlSet\Enum\$deviceId"
                $monitorIdSubkey = Join-Path -Path $monitor -ChildPath 'Device Parameters'

                if (Test-Path -Path $monitorIdSubkey) {
                    # Проверка наличия параметра EDID
                    if (Get-ItemProperty -Path $monitorIdSubkey -Name EDID -ErrorAction SilentlyContinue) {
                        $edidBytes = Get-ItemProperty -Path $monitorIdSubkey -Name EDID | Select-Object -ExpandProperty EDID
                        $edidString = [System.BitConverter]::ToString($edidBytes)

                       $startIndex = $edidString.IndexOf("00-00-00-FF-00-")
if ($startIndex -ne -1) {
    $startIndex += 15
    $endIndex = $edidString.IndexOf("-0", $startIndex)
    if ($endIndex -ne -1) {
        $serialNumberHex = $edidString.Substring($startIndex, $endIndex - $startIndex).Replace("-", "")
        $monserialNumber = ""
        for ($i = 0; $i -lt $serialNumberHex.Length; $i += 2) {
            $hexByte = $serialNumberHex.Substring($i, 2)
            $asciiByte = [System.Convert]::ToByte($hexByte, 16)
            $monserialNumber += [System.Text.RegularExpressions.Regex]::Replace([System.Text.Encoding]::ASCII.GetString([byte[]]($asciiByte)), "[^\w\d]", "")
        }
    }
    
}else {$monserialNumber = "-"}
                        $MonINFO += $monserialNumber

                        $startIndex1 = $edidString.IndexOf("00-00-00-FC-00-") + 15
                        $endIndex1 = $edidString.IndexOf("-0", $startIndex1)
                        $ModelHex1 = $edidString.Substring($startIndex1, $endIndex1 - $startIndex1).Replace("-", "")
                        $Model = ""
                        for ($i = 0; $i -lt $ModelHex1.Length; $i += 2) {
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
            }
        }

        if ($res.CurrentUser -like $null) {$res.CurrentUser = "_Нет активных сессий_"}
        if ($res.Monitor -like $null) {$res.Monitor = "Дисплей не подключен"}
        if ($res.MonInfo -like $null) {$res.MonInfo = "-"}
        sendMessage $URL_set $chat_id "Комп: * $($res.ComputerName) *`nЮзер: * $($res.CurrentUser) *`nПроц: $($res.Processor)`nRAM: $($res.RAMCapacity) | Type: $($res.MG) | Slot(s): $($res.RAMSlotsUsed)`nДиск(и): $($res.StorageType)`nFreeSpace: C: $($res.usedSpaceCInGB)Gb | D: $($res.usedSpaceDInGB)Gb `nSN:* $($res.Serialnumber) *`nМонитор(ы): $($res.Monitor)`nМоник-Инфо: $($res.Moninfo)`nMAC: $($res.MAC)`nUPtime: $($res.LastBootTime)  "
        $comp = $null
    }
    else {
        sendMessage $URL_set $chat_id "$comp не PING :("
        $comp = $null
    }

}
 


    if($return.text -like 'LAPS*')
    {
        $comp = $($return.text) -replace "LAPS ",""
        $compCheck = get-adcomputer $comp
        if ($compCheck -eq $Null){
                                    sendMessage $URL_set $chat_id "Такого компьютера нет в АД`nУ тебя есть два пути:`n1. Перезалить Windows;`n2. Изменить пароль локального админа с помощью: https://www.hirensbootcd.org/`n`nУдачи =)"
                                    $comp = $null
                                    }else{
                                            $password = get-adcomputer $comp -properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd
                                            $compCheck = $null
                                            $comp = $null
                                            if ($password -eq $null){
                                                                       sendMessage $URL_set $chat_id "У этого компьютера нет LAPS,`nпопробуй стандартный пароль.`nЕсли не подойдёт пароль, то для тебя есть два варианта:`n1. Перезалить Windows;`n2. Изменить пароль локального админа с помощью: https://www.hirensbootcd.org/`n`nУдачи =)"
                                                                       $comp = $null
                                                                       }else{
                                                                               sendMessage $URL_set $chat_id  $password
                                                                               $comp = $null
                                                                             }
                                          }
                        $password = $Null
      }

      if($return.text -like 'NAME*')
    {
        $pcname = $($return.text) -replace "NAME ",""
$i = 0
$b = 1
$a = $null
While ($i -eq 0)
    {
if ($b -lt 10){
$a = "$($pcname)0$($b)"
} else {
$a = "$($pcname)$b"
}
$Check = get-adcomputer $a | select -ExpandProperty name
if  ($Check -eq $a)
    {
    $b++
    $a = $null
    }else{
    sendMessage $URL_set $chat_id  "Свободное имя $a"
    $b = 1
    $i = 1
    $a = $null
            }
    }
}

if($return.text -like 'MSKNAME*')
    {
        $pcname = $($return.text) -replace "MSKNAME ",""

$b = 1
$a = $null
While ($i -eq 0){
$a = "$($pcname)$b"
$Check = get-adcomputer $a | select -ExpandProperty name
if  ($Check -eq $a)
    {
    $b++
    $a = $null
    }else{
    sendMessage $URL_set $chat_id  "Свободное имя $a"
    $b = 1
    $i = 1
    $a = $null
            }
    }
    }


   if($return.text -like 'Дукалис*'){
    $i++
                                    if(($i -eq 0) -or ($i -eq 1)){ 
                                                                    sendMessage $URL_set $chat_id "Я тут."
                                                                        }
                                    if($i -eq 2){
                                                    sendMessage $URL_set $chat_id "Я тут, приказывайте."
                                    }
                                    if($i -eq 3){
                                                    sendMessage $URL_set $chat_id "Видимо ты не знаешь или забыл мой функционал. Тыкни сюда: /info - я напомню. "
                                                    $i = 0
                                    }
    }



    if($return.text -in '/help', '/инфо', '/info'){
sendMessage $URL_set $chat_id "Я Дукалис и вот мой функционал:`n
Команды:`nLAPS `"*имя компа*`" - узнать пароль локального администратора;`n
NAME `"*имя компа без номера*`" - узнать свободный номер для компьютера;`n
PCINFO `"*имя компа*`" - текущая инфо по компу;`n
/Cryptopro - ключики и дистр КриптоПро;`n
/Powerbi - ссылка на свежий PowerBi;`n
/Cisco - дистр *ciscoAnyconnect*;`n
/Zoom - дистр Zoom клиента;`n
/Portal - прямые ссылки на *ROLF*овские оперсистемы;`n
/Quickpic - информация по квикпику;`n
/Scripts - да, да... это скрипты;`n
/Share - шары с софтом и полезностями.`n
`n
/help - справочная информация по боту`n
`n

Все возражения, предложения, пожелания и угрозы направлять сюда: dvandreev2@rolf.ru"
}

       [array]$Quickpic = @('Квикпик', 'Quickpic', '/Quickpic')
    if($return.text -in $Quickpic){
                                    sendMessage $URL_set $chat_id "Всех желающих пожаловаться в техподдержку, сюда: QuickPic@rolf.ru`nЕсли кто то просит его установить, перешли сообщение ниже ему в мессенджер или почту.`nЗапомни, мы не занимаемся поддержкой этого приложения. `nTHE END"
                                    sendMessage $URL_set $chat_id "Привет!`nЧто бы установить приложение quickpic переходи по ссылке:`nhttps://soft.isb.rolf.ru/qp/default.htm - открывать надо со смартфона.`nВ случае возникновения технических проблем, можно написать сюда: QuickPic@rolf.ru`nХорошего дня!"
                                    sendPhoto
                                   }
    
    [array]$Zoom = @('Зум', 'Zoom', '/Zoom')
    if($return.text -in $Zoom){
                                    sendMessage $URL_set $chat_id "Запуск по порядку:`n1.Дистр принудительной очистки старой версии клиента – \\alt-it-fs\Distrib\_Zoom\CleanZoom.exe`n2. msi нового клиента - \\alt-it-fs\Distrib\_Zoom\ZoomInstallerFull.msi"
                                    }

    [array]$CryptoPro = @('Криптопро', 'Cryptopro', '/Cryptopro')
    if($return.text -in $Cryptopro){
                                    sendMessage $URL_set $chat_id "КриптоПро, ключи:`nv4.x - 4040CA000001PTUV6VYPLG6TK`nv5.x - 505090301001K3WV3B6FR3AMX`n`nДистр:`nhttps://cryptopro.ru/products/csp/downloads`nЛогин: dvandreev2@rolf.ru`nПароль: Aa12345"
                                    sendMessage $URL_set $chat_id "Обновить ключ лицензии можно удалённо через реестр:`n1. Для 4.0 тут:`nHKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\7AB5E7046046FB044ACD63458B5F481C\InstallProperties`n2. Для 5.0 тут:`nHKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\08F19F05793DC7340B8C2621D83E5BE5\InstallProperties`nВ свойстве `"ProductID`" надо просто заменить ключ на актуальный."
                                    }
    [array]$Cisco = @('Циска','/Cisco', 'Cisco')
    if($return.text -in $Cisco){
                                    sendMessage $URL_set $chat_id "Свежая CiscoAnyConnect для всех ОС (Win/Nix/Mac): http://www.hostwaydcs.com/CISCO/AnyConnect"
                                    }

    [array]$Scripts = @('скрипты','script', 'scripst', 'скрипт', '/Scripts')
    if($return.text -in $Scripts){
                                    sendMessage $URL_set $chat_id "Скрипты тут: \\cl-it02\ADM-SUPPORT\Scripts\"
                                    }
	
	[array]$Powerbi = @('Поверби','Powerbi', '/Powerbi')
    if($return.text -in $Powerbi){
                                    sendMessage $URL_set $chat_id "Свежий PowerBi: https://www.microsoft.com/ru-ru/download/confirmation.aspx?id=58494"
                                    }

    	[array]$newYear = @('Поздравление','НГ','Новый год','newYear', '/newYear', '/NG')
    if($return.text -in $newYear){
# НГ
$s1 = Get-Random -InputObject @("с новым счастьем!", "365 новых дней - 365 новых шансов!", "наслаждайтесь каждым его моментом!", "примите мои искренние поздравления!", "годом Кролика!", "новый старт начинается сегодня!", "и пусть самые лучшие сюрпризы будут у вас впереди!")
$s2 = Get-Random -InputObject @("много новых достижений, крепкого здоровья и любви, пусть задуманное сбудется!", "чтобы этот год подарил много поводов для радости и счастливых моментов!", "чтобы будущий год принес столько радостей, сколько дней в году, и что бы каждый день дарил вам улыбку и частичку добра!", "Вам прекрасного года, полного здоровья и благополучия", "чтобы Кролик принёс в вашу семью любовь, нежность, взаимопонимание и счастье!", "всем в Новом году быть здоровыми, красивыми, любимым и успешными!", "чтобы сбылось все то, что вы пожелали. Все цели были достигнуты, а планы перевыполнены. Все плохое и неприятное осталось в уходящем году!")
$s3 = Get-Random -InputObject @("Новый год принесет много радостных и счастливых дней!", "каждый новый миг наступающего года приносит в дом счастье, везение, уют и теплоту!", "все, что мы планировали обязательно сбудется!", "наступающй год станет самым плодотворным годом в вашей жизни!", "год будет полон ярких красок, приятных впечатлений и радостных событий!", "этот год будет ВАШИМ годом!", "Новый год принесет все, о чем вы мечтаете и немного больше!")

                                    sendMessage $URL_set $chat_id "С Новым годом, $s1 Я желаю $s2 И пусть $s3"
                                    }

    [array]$Share = @('шары','shared', 'distr', 'дистрибутивы', '/Share')
    if($return.text -in $Share){
sendMessage $URL_set $chat_id "
Шары:`n
Главная шара: \\1\`n
Карлайн: \\cl-it02\SOFT\`n
Лахта: \\laht-itsrv\SOFT\`n
Аэропорт: \\aero-music\SOFT\`n
Алтуфьево: \\alt-it-fs\Distrib\`n
`n
Я больше не знаю шар. Хотите заделиться с коллегами своей шарой?`n
Пишите сюда: dvandreev2@rolf.ru"
}
     [array]$Doc = @('/Doc')
     if($return.text -in $Doc){
     $documentObject = get-item "D:\tgBots\AdmChatbot\Files\test.txt"
     sendPhoto $URL_photo $chat_id $documentObject
     }

                                   
    [array]$RolfPortals = @('Порталы','Прямые ссылки', 'Прямыессылки', '/Portal')
    if($return.text -in $RolfPortals){
sendMessage $URL_set $chat_id "АС Рольф: https://asrolf:10146/asrolf/root$.startup `n
АС Рольф-Отчеты: https://dp-asw2:10152/asrolf/root$.startup `n
ЕКБ: https://asrolf:10156/asrolf2/po_bm$.startup `n
ARMS: http://cr-arms-web:180/ARMS/ru/ `n
Web-табель: http://rolf-timeboard/ `n
Pronto X: https://dp-prontox-app-rolf/ `n
Uniplan: https://dp-uniplan-app-rolf/ `n
WEB - автомобили: https://asrolf:63146/apex/f?p=101:23:9333487394004:::::#no-back-button `n
WEB - клиенты: https://asrolf:63146/apex/f?p=123:6:9333487394004::NO:::#no-back-button `n
WEB - Автопрокат: https://asrolf:63146/apex/f?p=103:8:9333487394004:::::#no-back-button `n
WEB - Fishblue: https://asrolf:63146/apex/f?p=107:10:9333487394004:::::#no-back-button `n
WEB - Fleet: https://asrolf:63146/apex/f?p=106:321:9333487394004::NO::P0_TAB:FLEET#no-back-button `n
WEB - ЕРЛ: https://asrolf:63146/apex/f?p=105:17:9333487394004::NO:::#no-back-button `n
WEB - кузов: https://asrolf:63146/apex/f?p=106:14:9333487394004::NO::P0_TAB:BODYSHOP#no-back-button `n
WEB - сервис: https://asrolf:63146/apex/f?p=106:42:9333487394004::NO::P0_TAB:SERVICE#no-back-button `n
WEB - ОЗЧ: https://asrolf:63146/apex/f?p=106:300:9333487394004::NO::P0_TAB:PARTS#no-back-button `n
WEB - лояльность: https://asrolf:63146/apex/f?p=110:110:9333487394004::NO::P110_MODE:#no-back-button `n
WEB - страхование: https://asrolf:63146/apex/f?p=107:401:9333487394004::NO::P0_TAB:INSURANCE#no-back-button `n
WEB - Бронирование: https://asrolf:63146/apex/f?p=107:83:9333487394004::NO:::#no-back-button `n
WEB - Отчеты https://asrolf:63146/apex/f?p=106:38:9333487394004::::P0_TAB:RP#no-back-button `n"
                                    }
Write-host $URL
    Start-Sleep -s $timeout
    
}


<#
Это отправка файлов, но пока что этот функционал не внедрялся, не понятно что и зачем можно отправить в тг чат, что бы это было полезным.
Возможно APK каких либо классный приложений на смартфон.

$token = "000000000:1111111111111111111"
$chat_id = "11111111111"
$uri = "https://api.telegram.org/bot$Token/sendDocument"
$fileObject= get-item D:\tgBots\AdmChatbot\Files\test.txt
$Form = @{
        chat_id              = $chat_ID
        document             = $fileObject
        
    }#form
$invokeRestMethodSplat = @{
        Uri         = $Uri_document
        ErrorAction = 'Stop'
        Form        = $Form
        Method      = 'Post'
    }

Invoke-RestMethod @invokeRestMethodSplat
#>
