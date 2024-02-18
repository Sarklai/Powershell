# --- Читаем с конфиг файла: id бота, таймаут, tg_it юзеров которым разрешено работать с ботом ---

[xml]$xmlConfig = Get-Content -Path ("D:\tgBots\LAPSbot\tgLapsBot_LAPSConf.xml")
$token = $xmlConfig.config.system.token
$users = (($xmlConfig.config.system.users).Split(",")).Trim()

# Телеграмовые URLs
$URL_get = "https://api.telegram.org/bot$token/getUpdates"
$URL_set = "https://api.telegram.org/bot$token/sendMessage"

function getUpdates($URL)
{
    $json = Invoke-RestMethod -Uri $URL
    $data = $json.result | Select-Object -Last 1
    # Обнуляем переменные
    $text = $null
    $callback_data = $null

    # Нажатие на кнопку (кнопок нет, но возможно будут)
    if($data.callback_query)
    {  
        $callback_data = $data.callback_query.data
        $chat_id = $data.callback_query.from.id
        $f_name = $data.callback_query.from.first_name
        $l_name = $data.callback_query.from.last_name
        $username = $data.callback_query.from.username
    }
    # Обычное сообщение
    elseif($data.message)
    {
        $chat_id = $data.message.chat.id
        $text = $data.message.text
        $f_name = $data.message.chat.first_name
        $l_name = $data.message.chat.last_name
        $type = $data.message.chat.type
        $username = $data.message.chat.username
    }
    
    # Хэштейбл - так удобнее
    $ht = @{}
    $ht["chat_id"] = $chat_id
    $ht["text"] = $text
    $ht["f_name"] = $f_name
    $ht["l_name"] = $l_name
    $ht["username"] = $username
    $ht["callback_data"] = $callback_data

    # confirm
    Invoke-RestMethod "$($URL)?offset=$($($data.update_id)+1)" -Method Get | Out-Null
    
    return $ht
}
function sendMessage($URL, $chat_id, $text)
{
    $ht = @{
        text = $text
        parse_mode = "Markdown"
        chat_id = $chat_id
    }
    # Данные нужно отправлять в формате json
    $json = $ht | ConvertTo-Json
    # Никто не запрещает сделать и через Invoke-WebRequest
    # Method Post - т.к. отправляем данные, по умолчанию Get
    Invoke-RestMethod $URL -Method Post -ContentType 'application/json; charset=utf-8' -Body $json
}

# ---------------- НАЧАЛО ----------------

while($true) # вечный цикл
{
    $return = getUpdates $URL_get

    if($users -contains $return.chat_id) {

    if($return.text)
    {
        $comp = $($return.text)
        $compCheck = get-adcomputer $comp
        if ($compCheck -eq $Null){
        sendMessage $URL_set $return.chat_id "Такого компьютера нет"
        sendMessage $URL_set $return.chat_id "Введите имя компьютера:"
        $compCheck = $Null
        }else{
        $compCheck = $Null
        $password = get-adcomputer $comp -properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd
        if ($password -eq $Null){
        sendMessage $URL_set $return.chat_id "У этого компьютера нет LAPS, попробуйте стандартный пароль: 6548624"
        sendMessage $URL_set $return.chat_id "Введите имя компьютера:"
        }else{
        sendMessage $URL_set $return.chat_id $password
        sendMessage $URL_set $return.chat_id "Введите имя компьютера:"
            }
        }
        $password = $Null
        }
       }
       else
    {
        if($return.text)
        {
            sendMessage $URL_set $return.chat_id "Вы кто такие? Я вас не звал!"
        }
    }
    Start-Sleep -s 2
}