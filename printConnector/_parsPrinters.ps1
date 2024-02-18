# создаются списки по каждой локации

# Питер ---------------------------------------------------------

$printersVitebskiy = Get-Printer -ComputerName "linx-print-01" | sort-object name | Where-object -FilterScript {$_.name -like "cl-*"} | Select-Object -ExpandProperty Name

$printersPulkovo = Get-Printer -ComputerName "linx-print-01" |sort-object name | Where-object -FilterScript {$_.name -like "pul-*"} | Select-Object -ExpandProperty Name

$printersAeroport = Get-Printer -ComputerName "linx-print-01" |sort-object name | Where-object -FilterScript {$_.name -like "aero-*"} | Select-Object -ExpandProperty Name

$printersOktyabrskaya = Get-Printer -ComputerName "linx-print-02" | sort-object name | Where-object -FilterScript {$_.name -like "oct-*" -or $_.name -like "jlr-*" -or $_.name -like "gen-*" -or $_.name -like "mmc-*" -or $_.name -like "prsh-*" } | Select-Object -ExpandProperty Name

$printersPolustrovo = Get-Printer -ComputerName "linx-print-01" | sort-object name | Where-object -FilterScript {$_.name -like "pol-*"} | Select-Object -ExpandProperty Name

$printersLahta = Get-Printer -ComputerName "linx-print-02" | sort-object name | Where-object -FilterScript {$_.name -like "laht-*"} | Select-Object -ExpandProperty Name

# МСК -----------------------------------------------------------

$printersCentralOffice = Get-Printer -ComputerName "dlc-print-02" | sort-object name | Where-object -FilterScript {$_.name -like "CO-*"} | Select-Object -ExpandProperty Name


# Создание и наполнение XML файла -------------------------------

# Устанавливается форматирование
$xmlsettings = New-Object System.Xml.XmlWriterSettings
$xmlsettings.Indent = $true
$xmlsettings.IndentChars = "    "

# Задается имя файла и он создается (В дальнейшем перезаписывается).
$XmlWriter = [System.XML.XmlWriter]::Create("D:\testConfig\Printers.xml", $xmlsettings)
$xmlWriter.WriteStartDocument()
$xmlWriter.WriteProcessingInstruction("xml-stylesheet", "type='text/xsl' href='style.xsl'")

# Задается корневой тэг
$xmlWriter.WriteStartElement("Root")
  
    $xmlWriter.WriteStartElement("Carline") # <-- Start <Carline>

    foreach ($p in $printersVitebskiy){
        $xmlWriter.WriteElementString("Printer","$p")
        }

    $xmlWriter.WriteEndElement() # <-- End <Carline>

    $xmlWriter.WriteStartElement("Pulkovo") # <-- Start <Pulkovo>

    foreach ($p in $printersPulkovo){
        $xmlWriter.WriteElementString("Printer","$p")
        }

    $xmlWriter.WriteEndElement() # <-- End <Pulkovo>

    $xmlWriter.WriteStartElement("Aeroport") # <-- Start <Aeroport>

    foreach ($p in $printersAeroport){
        $xmlWriter.WriteElementString("Printer","$p")
        }

    $xmlWriter.WriteEndElement() # <-- End <Aeroport>

    $xmlWriter.WriteStartElement("Oktyabrskaya") # <-- Start <Oktyabrskaya>

    foreach ($p in $printersOktyabrskaya){
        $xmlWriter.WriteElementString("Printer","$p")
        }

    $xmlWriter.WriteEndElement() # <-- End <Oktyabrskaya>

    $xmlWriter.WriteStartElement("Polustrovo") # <-- Start <Polustrovo>

    foreach ($p in $printersPolustrovo){
        $xmlWriter.WriteElementString("Printer","$p")
        }

    $xmlWriter.WriteEndElement() # <-- End <Polustrovo>

    $xmlWriter.WriteStartElement("Lahta") # <-- Start <Lahta>

    foreach ($p in $printersLahta){
        $xmlWriter.WriteElementString("Printer","$p")
        }

    $xmlWriter.WriteEndElement() # <-- End <Lahta>
	
	$xmlWriter.WriteStartElement("CentralOffice") # <-- Start <CentralOffice>

    foreach ($p in $printersVitebskiy){
        $xmlWriter.WriteElementString("Printer","$p")
        }

    $xmlWriter.WriteEndElement() # <-- End <CentralOffice>

$xmlWriter.WriteEndElement() # <-- End <Root> 

# Завершение, сохранение, закрытие
$xmlWriter.WriteEndDocument()
$xmlWriter.Flush()
$xmlWriter.Close()