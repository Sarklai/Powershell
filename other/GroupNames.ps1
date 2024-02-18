#Скрипт для просмотра ИМЕН групп пользователя.
try
{
Write-Host "Введите логин пользователя: "
$UsrName = read-host
get-ADPrincipalGroupMembership $UsrName | ft -Property name -AutoSize
Read-Host -Prompt "Нажмите Enter что бы выйти"
}
catch
{
Write-Host "Такого пользователя нет!
"
.\GroupNames.ps1
}
