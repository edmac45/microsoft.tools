
param(
	[Parameter(HelpMessage="User account to provide Zenoss permissions")]
	[Alias('user', 'u')]
	[string]
	$login = 'benny',
	[Alias('force','f')]
	[switch]
	$force_update = $false
	)

########################################
#  ------------------------------------
#  ----------- Initialization  --------
#  ------------------------------------
########################################


#$login = 'zenny@zenoss.com'					# Domain Account
#$login = 'benny'                               # Local Account

# The following values will be set at runtime. They are place holders here.
$usersid

# Default settings
$inherit = $True      # Set to false (not recommended) if you do not want WMI Acl inheritance

$OBJECT_INHERIT_ACE_FLAG = 0x1
$CONTAINER_INHERIT_ACE_FLAG = 0x2

$objSDHelper = New-Object System.Management.ManagementClass Win32_SecurityDescriptorHelper

# Set account information

if($login.contains("@")){
	$arrlogin = $login.split("@")
	$arrdomain = $arrlogin[1].split(".")
    $domain = $arrdomain[0]
	$username = $arrlogin[0]
	$userfqdn = $login
}
else{
	$domain = $env:COMPUTERNAME
	$username = $login
	$userfqdn = "{1}\{0}" -f $username, $domain
}

# Prep event Log

function get_accessmask($permissions){
	<#
	$permissions = @("Enable","MethodExecute","ReadSecurity","RemoteAccess")
	#>

	$permTable = @{
		"enable" 				= 1;
		"methodexecute" 		= 2;
		"fullwrite"				= 4;
		"partialwrite"			= 8;
		"providerwrite"			= 0x10;
		"remoteaccess"			= 0x20;
		"readsecurity"			= 0x20000;
		"readfolder"			= 0x20089;
		"deleteperm"			= 0x10000;
		"writesecurity"			= 0x40000;
		"genericall"			= 0x10000000;
		"genericexecute"		= 0x20000000;
		"genericwrite"			= 0x40000000;
		"genericread"			= 0x80000000;
		"listcontents"			= 0x00000004;
        "dcomremoteaccess"      = 0x00000005;
        "readallprop"			= 0x00000010;
		"keyallaccess"			= 0xF003F;
		"keyread"				= 0x20019;
		"keywrite"				= 0x20006;
		"keyexecute"			= 0x20019;
		"keyenumeratesubkeys"	= 0x0004;
		"keyqueryvalue"			= 0x0001;
		"keysetvalue"			= 0x0002;
		"servicequeryconfig"	= 0x0001;
		"servicequeryservice"	= 0x0004;
		"servicestart"			= 0x0010;
		"servicestop"			= 0x0020;
		"serviceinterrogate"    = 0x0080
	}

	$accessMask = 0
	foreach ($perm in $permissions) {
		$perm = $perm.ToLower()
		if($permTable.ContainsKey($perm)){
			$accessMask += $permTable[$perm]
		}
		else {
		    throw "Unknown permission: $perm"
		}
	}
	return $accessMask
}

function update_sddl($sddlstart, $usersid, $accessMask){
	$securitydescriptor = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList @($false, $false, $sddlstart);
 	$securitydescriptor.DiscretionaryAcl.AddAccess("Allow", $usersid, $accessMask,"None","None")
	return $securitydescriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
}

function add_user_to_service($service, $accessMask){
	$servicesddlstart = [string](CMD /C "sc sdshow `"$service`"")
	if(($servicesddlstart.contains($usersid) -eq $False) -or ($force_update -eq $true)){
		$servicesddlnew = update_sddl $servicesddlstart $usersid $accessMask
		$ret = CMD /C "sc sdset $service $servicesddlnew"
        if ($ret[0] -match '.FAILED.') {
            $reason = $ret[2]
            $message = "User: $userfqdn was not added to service $service.`n`tReason:  $reason"
        } else {
            $message = "User: $userfqdn added to service $service."
        }
		##send_event $message 'Information'
	}
	else{
		$message = "Service $service already contains permission for user $userfqdn"
		write-output $message
		##send_event $message 'Information'
	}
}

$services = get-wmiobject -query "Select * from Win32_Service" | Where-Object {$_.name -like "DPS"} ##"*sql*"}
$serviceaccessmap = get_accessmask @("servicequeryconfig","servicequeryservice","readallprop","readsecurity","serviceinterrogate")
add_user_to_service 'SCMANAGER' $serviceaccessmap
foreach ($service in $services){
	add_user_to_service $service.name $serviceaccessmap
}