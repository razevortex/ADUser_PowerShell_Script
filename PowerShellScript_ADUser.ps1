Import-Module ActiveDirectory
#Import the CSV File with the Userdata change Path as needed
$ADUsers = Import-Csv "c:\Aduser-csv.csv" -Delimiter ";"
foreach ($User in $ADUsers)
{
$Username  	= $User.Username
$Displayname= $User.Displayname
$Password  	= $User.Password
$Firstname  = $User.Firstname
$Lastname  	= $User.Lastname
$Initials	= $User.Initials
$Email      = $User.Email
$Title   	= $User.Title
$Company    = $User.Company
$Department = $User.Department
$HomeDir	= $User.Dir
$HomeDrive	= $User.Drive

#Check to see if the user already exists in AD
if (Get-ADUser -F {SamAccountName -eq $Username})
{
     #If user does exist, give a warning
     Write-Warning "A user account with username $Username already exist in Active Directory."
}
else
{
    #User does not exist then proceed to create the new user account
    New-ADUser `
        -SamAccountName $Username `
        -UserPrincipalName "$Username@ebt.local" `
        -Name $Displayname `
        -GivenName $Firstname `
        -Surname $Lastname `
		-Initials $Initials `
        -Enabled $True `
        -DisplayName $Displayname `
        -Company $Company `
        -EmailAddress $Email `
        -Title $Title `
        -Department $Department `
		-HomeDirectory $HomeDir `
		-HomeDrive $HomeDrive `
        -AccountPassword (convertto-securestring $Password -AsPlainText -Force) -ChangePasswordAtLogon $True
	#Check if User was created
	Write-Host ("Useraccount for $Username created")	
	if (Get-ADUser -F {SamAccountName -eq $Username})
{
		#Then create the HomeDirectory with permissions
		$User = Get-ADUser -Identity $Username
		Set-ADUser $Username -HomeDrive $HomeDrive -HomeDirectory $HomeDir -ea Stop
		$homeShare = New-Item -path $HomeDir -ItemType Directory -force -ea Stop
		$acl = Get-Acl $homeShare
		$FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
		$AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
		$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
		$PropagationFlags = [System.Security.AccessControl.PropagationFlags]"InheritOnly"
		$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($User.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
		$acl.AddAccessRule($AccessRule)
		Set-Acl -Path $homeShare -AclObject $acl -ea Stop
		Write-Host ("HomeDirectory created for $Username")
}
}
}
