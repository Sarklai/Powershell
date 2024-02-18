Add-Type -Assemblyname System.Windows.Forms
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()


<# variables ------------------------------------------------------------------------------------------------------------- #>


# Список для комбобокса. 
$locations = @("Витебский","Пулково","Аэропорт","Октябрьская","Полюстровский","Лахта","ЦО")

# Уже подключенные принтеры
$localPrinters = get-printer | sort-object name | where-object -filter {$_.Type -eq "Connection"} | select -expandproperty name | foreach { $_ -replace "..\w*-\w*-\d\d.","" }

<# functions ------------------------------------------------------------------------------------------------------------ #>


# Напоминалка: Popup(<Text>,<SecondsToWait>,<Title>,<Type>)

# Информационное сообщение
function InformationMessage ($title,$text){

$wshell = New-Object -ComObject Wscript.Shell
$Output = $wshell.Popup($text , 0 , $title , 64)

}

# Сообщение об ошибке
function ErrorMessage ($title,$text){

$wshell = New-Object -ComObject Wscript.Shell
$Output = $wshell.Popup($text , 0 , $title , 16)

}


### Проверяет выбран принтер для подключения или нет и в зависимости от этого делает кнопку активной
function EnableButtonConnectPrinter {

if ($listBoxServerPrinters.SelectedItem -ne $null)

    {
        $buttonConnectPrinter.Enabled = $True
    }
}

function EnableButtonRemovePrinter {

if ($listBoxLocalPrinters.SelectedItem -ne $null)

    {
        $buttonRemovePrinter.Enabled = $True
    } else {
            $buttonRemovePrinter.Enabled = $False
            }
}


<# Обновляет ЛистБокс с подключаемыми принтерами при смене локации.
   Сначала пробовал:
   Парсить принтсервер и заранее загруать списки для каждой локации - долго и занимает 30 сек.
   Парсить принтсервер и фильтровать конкретный список при смене локации - тоже по 2-4 секунды занимает и программа подвисает.
   По этому на компьютере CL-IT02 ежедневно срабатывает скрипт и формирует xml файлик со списком принтеров для каждой локации программа забирает с этого файлика:
   \\cl-it02\testPrintConnector\Printers.xml
   Это заметно ускоряет её работу. #>

function RefreshPrinterList {

$listBoxServerPrinters.Items.Clear()
$buttonConnectPrinter.Enabled = $False

if($comboBoxLocation.Text -eq "Витебский")
{
    $global:printServer = "linx-print-01"
    $PrintersVitebskiy = Select-Xml -Path "\\cl-it02\testPrintConnector\Printers.xml" -XPath '/Root/Carline/Printer' | ForEach-Object { $_.Node.InnerXML }
        $listBoxServerPrinters.Items.AddRange($PrintersVitebskiy)
}

if($comboBoxLocation.text -eq "Пулково")
{
    $global:printServer = "linx-print-01"
    $printersPulkovo = Select-Xml -Path "\\cl-it02\testPrintConnector\Printers.xml" -XPath '/Root/Pulkovo/Printer' | ForEach-Object { $_.Node.InnerXML }
        $listBoxServerPrinters.Items.AddRange($printersPulkovo)
}

if($comboBoxLocation.text -eq "Аэропорт")
{
    $global:printServer = "linx-print-01"
    $printersAeroport = Select-Xml -Path "\\cl-it02\testPrintConnector\Printers.xml" -XPath '/Root/Aeroport/Printer' | ForEach-Object { $_.Node.InnerXML }
        $listBoxServerPrinters.Items.AddRange($printersAeroport)
}

if($comboBoxLocation.text -eq "Октябрьская")
{
    $global:printServer = "linx-print-02"
    $printersOktyabrskaya = Select-Xml -Path "\\cl-it02\testPrintConnector\Printers.xml" -XPath '/Root/Oktyabrskaya/Printer' | ForEach-Object { $_.Node.InnerXML }
        $listBoxServerPrinters.Items.AddRange($printersOktyabrskaya)
}

if($comboBoxLocation.text -eq "Полюстровский")
{
    $global:printServer = "linx-print-01"
    $printersPolustrovo = Select-Xml -Path "\\cl-it02\testPrintConnector\Printers.xml" -XPath '/Root/Polustrovo/Printer' | ForEach-Object { $_.Node.InnerXML }
        $listBoxServerPrinters.Items.AddRange($printersPolustrovo)
}

if($comboBoxLocation.text -eq "Лахта")
{
    $global:printServer = "linx-print-02"
    $printersLahta = Select-Xml -Path "\\cl-it02\testPrintConnector\Printers.xml" -XPath '/Root/Lahta/Printer' | ForEach-Object { $_.Node.InnerXML }
        $listBoxServerPrinters.Items.AddRange($printersLahta)
}

if($comboBoxLocation.text -eq "ЦО")
{
    $global:printServer = "dlc-print-02"
    $printersLahta = Select-Xml -Path "\\cl-it02\testPrintConnector\Printers.xml" -XPath '/Root/CentralOffice/Printer' | ForEach-Object { $_.Node.InnerXML }
        $listBoxServerPrinters.Items.AddRange($printersLahta)
}

{Return}

}


### Удаляет выбранный принтер
function ClickButtonRemovePrinter {
    
    # Почему то находясь в листбоксе оно имеет много лишних полей, но забрав SelectedItem в переменную - такой проблемы нет.
    $removingPrinter = $listBoxLocalPrinters.SelectedItem

    # Формирует целевой принтер в нужный вид для команды remove-printer
    $linkRemovingPrinter = get-printer | where-object -filter {$_.name -like "*$($removingPrinter)"} | select -expandproperty name

    # помещаю целевую команду в джобу, шоб визуальная форма не подвисала на момент выполнения.
    $job = Start-Job -ScriptBlock {Remove-Printer -name "$using:linkRemovingPrinter"}

    do { [System.Windows.Forms.Application]::DoEvents() } until ($job.State -eq "Completed")

    # Обновляет список подключенных принтеров
    Clear-Variable -Name localPrinters

    $localPrinters = get-printer | sort-object name | where-object -filter {$_.Type -eq "Connection"} | select -expandproperty name | foreach { $_ -replace "..\w*-\w*-\d\d.","" }
    
    $listBoxLocalPrinters.Items.Clear()
    $listBoxLocalPrinters.Items.AddRange($localPrinters)

    InformationMessage "Внимание!" "Принтер $removingPrinter удален!"

    # Отключаю кнопку
    EnableButtonRemovePrinter

}


### Подключает выбранный принтер.
function ClickButtonConnectPrinter {

    # Почему то находясь в листбоксе оно имеет много лишних полей, но забрав SelectedItem в переменную - такой проблемы нет.
    $connectingPrinter = $listBoxServerPrinters.SelectedItem

    if ($localPrinters -contains $connectingPrinter) {
        InformationMessage "Внимание!" "Принтер $connectingPrinter уже подключен!"
    }

    else {
    
    # Создет прогрессбар
    $ProgressBar = New-Object System.Windows.Forms.ProgressBar
    $ProgressBar.Location = New-Object System.Drawing.Size(5,100)
    $ProgressBar.Size = New-Object System.Drawing.Size(120,10)
    $ProgressBar.Style = "Marquee"
    $ProgressBar.MarqueeAnimationSpeed = 20
    $ProgressBar.visible
    # Создет лейбл над прогрессбаром
    $labelProgressBar = New-Object System.Windows.Forms.Label
    $labelProgressBar.Text = "Подключение..."
    $labelProgressBar.Location = New-Object System.Drawing.Point(5,80)
    $labelProgressBar.AutoSize = $true
    # Делаю прогрессбар видимым
    $mainForm.Controls.Add($labelProgressBar)
    $mainForm.Controls.Add($ProgressBar)

    <# Создет джоб и помещает в него команду для подключения принтера: (New-Object -ComObject WScript.Network).AddWindowsPrinterConnection("\\$($using:printServer)\$($using:connectingPrinter)")}
       Выбор пал на эту команду т.к. она подключает принтер мгновенно при наличии в ОС нужного драйвера, иначе она его скачивает и так же довольно быстро подключает. К переменным добавляется приставка $using: - это необходимо из за области видимости, без этой приставки внутри джобы не удастся получить значения переменных #>
    $job = Start-Job -ScriptBlock {
        (New-Object -ComObject WScript.Network).AddWindowsPrinterConnection("\\$($using:printServer)\$($using:connectingPrinter)")}

        do { [System.Windows.Forms.Application]::DoEvents() } until ($job.State -eq "Completed")

    # Убивает джобу шоб не висела
    Remove-Job -Job $job -Force

    # Очищет переменную с локальными принтерами и далее по новой собирает аррай с ними, что бы пользователь наглядно увидел результат
    Clear-Variable -Name localPrinters
    $localPrinters = get-printer | sort-object name | where-object -filter {$_.Type -eq "Connection"} | select -expandproperty name | foreach { $_ -replace "..\w*-\w*-\d\d.","" }

    # Обновляет список локальных принтеров в листБоксе
    $listBoxLocalPrinters.Items.Clear()
    $listBoxLocalPrinters.Items.AddRange($localPrinters)
    
    # Прячет лейбл и прогрессбар
    $labelProgressBar.hide()
    $ProgressBar.hide()

    if ($connectingPrinter -in $localPrinters) {
    
    InformationMessage "Внимание!" "Принтер $connectingPrinter успешно подключен!"

    } else {
        
        ErrorMessage "ОШИБКА!" "Доступ к принтеру $connectingPrinter запрещён!`nОбратитесь к системному администратору."
            
            }

    {Return}

       }


    }


# gui -------------------------------------------------------------------------------------------------------------------

$labelLocation = New-Object System.Windows.Forms.Label
$labelLocation.Text = "Локация:"
$labelLocation.Location = New-Object System.Drawing.Point(5,20)
$labelLocation.AutoSize = $true

$labelLocalPrinters = New-Object System.Windows.Forms.Label
$labelLocalPrinters.Text = "Подключенные:"
$labelLocalPrinters.Location = New-Object System.Drawing.Point(135,20)
$labelLocalPrinters.AutoSize = $true

$comboBoxLocation = New-Object System.Windows.Forms.ComboBox
$comboBoxLocation.Location = New-Object System.Drawing.Point(5,40)
$comboBoxLocation.Size = New-Object System.Drawing.Size(110,20)
$comboBoxLocation.Height = 100
$comboBoxLocation.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$comboBoxLocation.add_SelectedIndexChanged({RefreshPrinterList})

$comboBoxLocation.Items.AddRange($locations)

$labelServerPrinters = New-Object System.Windows.Forms.Label
$labelServerPrinters.Text = "Можно подключить:"
$labelServerPrinters.Location = New-Object System.Drawing.Point(275,20)
$labelServerPrinters.AutoSize = $true

$listBoxLocalPrinters = New-Object System.Windows.Forms.ListBox
$listBoxLocalPrinters.Location  = New-Object System.Drawing.Point(130,40)
$listBoxLocalPrinters.Size = New-Object System.Drawing.Size(130,140)
$listBoxLocalPrinters.add_SelectedIndexChanged({EnableButtonRemovePrinter})
if ($localPrinters -eq $null){
    
    $listBoxLocalPrinters.Items.AddRange(' ')

    } else {
                $listBoxLocalPrinters.Items.AddRange($localPrinters)
            }


$listBoxServerPrinters = New-Object System.Windows.Forms.ListBox
$listBoxServerPrinters.Location  = New-Object System.Drawing.Point(270,40)
$listBoxServerPrinters.Size = New-Object System.Drawing.Size(130,140)
$listBoxServerPrinters.add_SelectedIndexChanged({EnableButtonConnectPrinter})

$buttonRemovePrinter = New-Object System.Windows.Forms.Button
$buttonRemovePrinter.Location = New-Object System.Drawing.Size(5,120)
$buttonRemovePrinter.Size = New-Object System.Drawing.Size(120,25)
$buttonRemovePrinter.Text = "Удалить"
$buttonRemovePrinter.Enabled = $False
$buttonRemovePrinter.add_Click({ClickButtonRemovePrinter});

$buttonConnectPrinter = New-Object System.Windows.Forms.Button
$buttonConnectPrinter.Location = New-Object System.Drawing.Size(5,150)
$buttonConnectPrinter.Size = New-Object System.Drawing.Size(120,25)
$buttonConnectPrinter.Text = "Подключить"
$buttonConnectPrinter.Enabled = $False
$buttonConnectPrinter.add_Click({ClickButtonConnectPrinter});

$mainForm = New-Object System.Windows.Forms.Form
$mainForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
$mainForm.Text ='Подключить принтер'
$mainForm.Width = 420
$mainForm.Height = 220
$mainForm.BackColor = "0xFFEEEEF2"

# Spawn gui -----------------------------------------------------------------------------------------------------------

$mainForm.Controls.Add($labelLocation)
$mainForm.Controls.Add($labelLocalPrinters)
$mainForm.Controls.Add($comboBoxLocation)
$mainForm.Controls.Add($labelServerPrinters)
$mainForm.Controls.Add($ListBoxLocalPrinters)
$mainForm.Controls.Add($ListBoxServerPrinters)
$mainForm.Controls.Add($buttonRemovePrinter)
$mainForm.Controls.Add($ButtonConnectPrinter)


$mainForm.ShowDialog()

