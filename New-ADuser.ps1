Import-Module ActiveDirectory

Get-ADOrganizationalUnit -Filter 'Name -like "*"' | FT Name, DistinguishedName -A 

$Name = Read-Host "Please Enter User Name"
$Path = Read-Host "Please Enter Path"
$Group = Read-Host "Please Enter Group Name"

New-ADUser `
 -Name $Name `
 -Path $Path `
 -SamAccountName $Name `
 -DisplayName $Name `
 -AccountPassword (ConvertTo-SecureString "MyP@ssword123" -AsPlainText -Force) `
 -ChangePasswordAtLogon $true  `
 -Enabled $true
Add-ADGroupMember $Group $Name

If ($Name) { 
    $Name = $Name.ToUpper().Trim() 
    $Res = (Get-ADPrincipalGroupMembership $Name | Measure-Object).Count 
    If ($Res -GT 0) { 
        Write-Output "`n" 
        Write-Output "The User $Name Is A Member Of The Following Groups:" 
        Write-Output "===========================================================" 
        Get-ADPrincipalGroupMembership $Name | Select-Object -Property Name, GroupScope, GroupCategory | Sort-Object -Property Name | FT -A 
    } 
}