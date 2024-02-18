#Просмотр членов группы
write-host 'Введи название группы'
$UsrGroup =Read-Host
Get-ADGroupMember -Identity $UsrGroup -Recursive | ft name
Read-Host -Prompt "Нажмите Enter что бы выйти"