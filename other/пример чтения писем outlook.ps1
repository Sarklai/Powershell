### PowerShell Парсинг п\я outlook

#Кусок создает COM объект для работы с outlook приложением
Clear-Host
$curDate = Get-Date
$olFolderInbox = 6
$outlook = new-object -com outlook.application;
$namespace = $outlook.GetNameSpace("MAPI");
$inbox = $mapi.GetDefaultFolder("$olFolderInbox")
$targetfolder = $inbox.Folders | ? { $_.name -eq "Администраторы Пулково" }


foreach ($letter in $targetfolder.Items)
{
   if(($letter.TaskSubject -like "В вашу Команду назначена Заявка*") -and ($curDate -gt $letter.SentOn))
   {

        if ($letter.Body -match "Тема: Уведомление о переводе сотрудника без ПК#")
        {
            write-host $letter.TaskSubject
            write-host $letter.SentOn
            write-host $letter.Body
        }

   }
}
