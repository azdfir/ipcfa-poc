<#
.SYNOPSIS
    Creates a fully functional 3-tier IaaS Environment (Presnetation=Web, Application=App, Data=DB)

.DESCRIPTION
    This is designed to be run from Azure cloud shell (PowerShell).  It will create 6 Linux VMs and 2 Windows VM.
	The Linix VMs will be intiiated using Cloud-init scripts to download and build reverse proxy and a dummy applciation. 
	The Cloud-init scripts provied should reside witin the same directory as the IaaS script. 
    The script will also create all the IaaS components, including storage accounts and load balancers and avilability zones. 
  
.EXAMPLE
  ./azDF_pocDeploy.ps1 -resourceGroup 3teir-iaas-rg -location westus
#>

param (
    # The resources group to be created.
    [Parameter(Mandatory = $true)]
    [string]
    $resourceGroup,

    # The Azure location for which the IaaS will be created
    [Parameter(Mandatory = $true)]
    [string]
    $location
)

$ErrorActionPreference = 'Stop'

############################## Variables ######################################
#Networks
$virtualNetworkName = "zprod-vnet"
$virtualNetwork = "10.10.0.0/16"
$webTierSubnetName = "zweb-subnet"
$webTierSubnetPrefix = "10.10.10.0/24"
$appTierSubnetName = "zapp-subnet"
$appTierSubnetPrefix = "10.10.20.0/24"
$databaseTierSubnetName = "zdb-subnet"
$databaseTierSubnetPrefix = "10.10.30.0/24"
$jumpSubnetName = "zmgmt-subnet"
$jumpSubnetPrefix = "10.10.0.0/24"

#Virtual machines 
$webTierVmCount = 3
$appTierVmCount = 3
$databaseTierVmCount = 2
$availSetName = "zha-set-"
$webTierVmName = "wzeb-vm"
$appTierVmName = "zapp-vm"
$databaseTierVmName = "zdb-vm"
$jumpVmName = "zmgmt-vm"
$webTierVmNicName = "$webTierVmName"+"-nic"
$appTierVmNicName = "$appTierVmName"+"-nic"
$databaseTierVmNicName = "$databaseTierVmName"+"-nic"
$JumVmNicName = "$jumpVmName"+"-nic"

#Network Security Groups
$webNSGName = "zweb-nsg"
$appNSGName = "zapp-nsg"
$databaseNSGName = "zdb-nsg"
$jumpNSGName = "zmgmt-nsg"
$remoteAllowedCIDR = "0.0.0.0/0"

#Load balancers 
$zwebLoadBalancerName = "zweb-lb-front"
$zappLoadBalancerName = "zapp-lb-back"

#Public IP addresses
$weblbIPAddressName = "zweb-lb-ip"
$jumpIPAddressName = "zmgmt-ip"

#Administrator account
$adminUsername = "zadmin"

############################## Tags ######################################
$displayName = "VM Storage Accounts"
$quickstartName = "zprod-iaas"
$provider = "IPCFA-DFIR"
$tags = @{
    displayName=$displayName;
    quickstartName=$quickstartName
    provider=$provider
}

########################## Create RG & Storage #################################
Write-Output "########################################"
Write-Output "1/11 Creating RG & Storage accounts ... "
Write-Output "########################################"
try {
	New-AzResourceGroup -Name $resourceGroup -Location $location -Tag $tags
}
catch {
	Write-Host $_
}

$cxt=Get-AzContext
$uniqueStartString = "zsto"+ $cxt.Account.Id.split('@')[0].ToLower()
$saName = ($uniqueStartString+"vmdisks") 
#Limiting storage units name 
if($saName.Length -gt 23)
{
    $saName = $saName.Substring(0,23) 
}
$saccts = @()
try {
	for($i=1; $i -le 4 ;$i++)
	{
		$saccts += New-AzStorageAccount -ResourceGroupName $resourceGroup `
		  -Name "$saName$i" `
		  -Location $location `
		  -SkuName Standard_GRS `
		  -Kind StorageV2  -Tag $tags
	}
}
catch {
	Write-Host $_
}
Write-Output "1/11 Creating RG & Storage accounts ... Done"

##Storage account for the diagnostics only
$digStorageAccName = "$uniqueStartString"+"diags"
try {
	$digStorageAcc = New-AzStorageAccount -ResourceGroupName $resourceGroup `
		-Name $digStorageAccName `
		-Location $location `
		-SkuName Standard_LRS `
		-Kind StorageV2 -Tag $tags
}
catch {
	Write-Host $_
}
########################## Network Security Groups (NSG) #################################
Write-Output "##########################################"
Write-Output "2/11 Creating network security groups ... "
Write-Output "##########################################"
try {
	#NSG for Web vms

	$rule1 = New-AzNetworkSecurityRuleConfig -Name "HTTP-allow" -Description "Allow HTTP" `
		-Access Allow -Protocol Tcp -Direction Inbound -Priority 110 -SourceAddressPrefix `
		$remoteAllowedCIDR -SourcePortRange * -DestinationAddressPrefix $webTierSubnetPrefix -DestinationPortRange 80

	$rule2 = New-AzNetworkSecurityRuleConfig -Name "HTTPS-allow" -Description "Allow HTTPS" `
		-Access Allow -Protocol Tcp -Direction Inbound -Priority 120 -SourceAddressPrefix `
		$remoteAllowedCIDR -SourcePortRange * -DestinationAddressPrefix $webTierSubnetPrefix -DestinationPortRange 443

	$WebNsg = New-AzNetworkSecurityGroup -ResourceGroupName $resourceGroup -Location $location -Name `
		$webNSGName -SecurityRules $rule1,$rule2 -Tag $tags

	#NSG for App vms
	$AppNsg = New-AzNetworkSecurityGroup -ResourceGroupName $resourceGroup -Location $location -Name $appNSGName -Tag $tags

	#Rule to allow SQL Server connections on port 1433
	$NsgRuleSQL = New-AzNetworkSecurityRuleConfig -Name "MSSQLRule"  -Protocol Tcp `
	   -Direction Inbound -Priority 101 -SourceAddressPrefix "10.0.2.0/24" -SourcePortRange * `
	   -DestinationAddressPrefix * -DestinationPortRange 1433 -Access Allow

	#NSG for Database vms
	$DBNsg = New-AzNetworkSecurityGroup -ResourceGroupName $resourceGroup -Location $location -Name $databaseNSGName `
				 -SecurityRules $NsgRuleSQL -Tag $tags

	#NSG for Jump server
	$ruleSSH = New-AzNetworkSecurityRuleConfig -Name "SSH-allow" -Description "Allow SSH" `
		-Access Allow -Protocol Tcp -Direction Inbound -Priority 120 -SourceAddressPrefix `
		$remoteAllowedCIDR -SourcePortRange * -DestinationAddressPrefix $jumpSubnetPrefix -DestinationPortRange 22

	$JumpNsg = New-AzNetworkSecurityGroup -ResourceGroupName $resourceGroup -Location $location -Name `
		$jumpNSGName -SecurityRules $ruleSSH -Tag $tags
}
catch {
	Write-Host $_
}
Write-Output "2/11 Creating network security groups ... Done!"

########################## Create public IPs ##############################
Write-Output "######################################"
Write-Output "3/11 Creating public IP addresses ... "
Write-Output "######################################"
try {
	$JumpIPAdd =  New-AzPublicIpAddress -ResourceGroupName $resourceGroup -Name $jumpIPAddressName `
		-Location $location -AllocationMethod Static -DomainNameLabel "jump$uniqueStartString$resourceGroup" `
		-idleTimeoutInMinutes 4 -Tag $tags

	$WebIPAdd = New-AzPublicIpAddress -ResourceGroupName $resourceGroup -Name $weblbIPAddressName `
		-Location $location -AllocationMethod Static -DomainNameLabel "web$uniqueStartString$resourceGroup" `
		-idleTimeoutInMinutes 4 -Sku Standard -Tag $tags
}
catch {
	Write-Host $_
}
Write-Output "3/11 Creating public IP addresses ... Done!"

########################## Create VNET & Subnets ###############################
Write-Output "###################################"
Write-Output "4/11 Creating VNet and subnets ... "
Write-Output "###################################"
try {
	$webTierSubnet = New-AzVirtualNetworkSubnetConfig -Name $webTierSubnetName -AddressPrefix $webTierSubnetPrefix `
		-NetworkSecurityGroup $WebNsg
	$appTierSubnet  = New-AzVirtualNetworkSubnetConfig -Name $appTierSubnetName  -AddressPrefix $appTierSubnetPrefix `
		-NetworkSecurityGroup $AppNsg
	$DbTierSubnet  = New-AzVirtualNetworkSubnetConfig -Name $databaseTierSubnetName  -AddressPrefix $databaseTierSubnetPrefix `
		-NetworkSecurityGroup $DBNsg
	$JumpSubnet  = New-AzVirtualNetworkSubnetConfig -Name $jumpSubnetName  -AddressPrefix $JumpSubnetPrefix `
		-NetworkSecurityGroup $JumpNsg

	# Creating VNet
	$vnet = New-AzVirtualNetwork -Name $virtualNetworkName -ResourceGroupName $resourceGroup -Location `
		$location -AddressPrefix $virtualNetwork -Subnet $webTierSubnet,$appTierSubnet,$DbTierSubnet,$JumpSubnet -Tag $tags
}
catch {
	Write-Host $_
}
Write-Output "4/11 Creating VNet and subnets ... Done! "

######################## Create the availability Sets ########################
Write-Output "####################################"
Write-Output "5/11 Creating availability Sets ... "
Write-Output "####################################"
try {
	$AvSet = @()
	# 3 Availability Sets for Web VMs, App VMs, and DB VMs
	for($i=1; $i -le 3 ;$i++)
	{
		$AvSet += New-AzAvailabilitySet -ResourceGroupName $resourceGroup -Name "$availSetName$i"  -Location $location `
			-Sku Aligned -platformFaultDomainCount 2 -PlatformUpdateDomainCount 5 -Tag $tags
	}
}
catch {
	Write-Host $_
}
Write-Output "5/11 Creating availability Sets ... Done!"

##################### Create the traffic Load-Balancers #######################
Write-Output "########################################"
Write-Output "6/11 Creating network Load-balancers .. "
Write-Output "########################################"
#Creating the external LB
try {
	$feip = New-AzLoadBalancerFrontendIpConfig -Name $zwebLoadBalancerName -PublicIpAddress $WebIPAdd
	$bepool = New-AzLoadBalancerBackendAddressPoolConfig -Name $zappLoadBalancerName

	$probeWebHttp = @{
		Name = 'weblbProbeHttp'
		Protocol = 'tcp'
		Port = '80'
		IntervalInSeconds = '5'
		ProbeCount = '2'
	}
	$weblbProbeHttp = New-AzLoadBalancerProbeConfig @probeWebHttp

	$probeWebHttps = @{
		Name = 'weblbProbeHttps'
		Protocol = 'tcp'
		Port = '443'
		IntervalInSeconds = '5'
		ProbeCount = '2'
	}
	$weblbProbeHttps = New-AzLoadBalancerProbeConfig @probeWebHttps

	#Create the LB rules
	$lbrule1 = @{
		Name = 'LBRuleForlb80IP'
		Protocol = 'tcp'
		FrontendPort = '80'
		BackendPort = '80'
		IdleTimeoutInMinutes = '5'
		FrontendIpConfiguration = $feip
		BackendAddressPool = $bePool
		Probe = $weblbProbeHttp
	}
	$rule1 = New-AzLoadBalancerRuleConfig @lbrule1 -EnableTcpReset -DisableOutboundSNAT

	$lbrule2 = @{
		Name = 'LBRuleForlb443IP'
		Protocol = 'tcp'
		FrontendPort = '443'
		BackendPort = '443'
		IdleTimeoutInMinutes = '5'
		FrontendIpConfiguration = $feip
		BackendAddressPool = $bePool
		Probe = $weblbProbeHttps
	}
	$rule2 = New-AzLoadBalancerRuleConfig @lbrule2 -EnableTcpReset -DisableOutboundSNAT

	#Create the load balancer resource
	$loadbalancer = @{
		ResourceGroupName = $resourceGroup
		Name = 'web-lb'
		SKU = "Standard"
		Location = $location
		FrontendIpConfiguration = $feip
		BackendAddressPool = $bePool
		LoadBalancingRule = $rule1,$rule2
		Probe = $weblbProbeHttp,$weblbProbeHttps
	}
	$webLb = New-AzLoadBalancer @loadbalancer -Tag $tags

	#Create the Internal LB
	$feip = New-AzLoadBalancerFrontendIpConfig -Name "loadBalancerFrontEnd" -Subnet $vnet.Subnets[0]
	$bepoolInternal = New-AzLoadBalancerBackendAddressPoolConfig -Name "loadBalancerBackend"

	$ProbeSSH = @{
		Name = 'internallbProbeSSH'
		Protocol = 'tcp'
		Port = '22'
		IntervalInSeconds = '15'
		ProbeCount = '2'
	}
	$internallbProbeSSH = New-AzLoadBalancerProbeConfig @ProbeSSH

	#Create the LB rules
	$lbrule1 = @{
		Name = 'internallbruleSSH'
		Protocol = 'tcp'
		FrontendPort = '22'
		BackendPort = '22'
		IdleTimeoutInMinutes = '15'
		FrontendIpConfiguration = $feip
		BackendAddressPool = $bepoolInternal
		Probe = $internallbProbeSSH
	}
	$rule1 = New-AzLoadBalancerRuleConfig @lbrule1 -EnableTcpReset -DisableOutboundSNAT

	#Create the load balancer resource
	$loadbalancer = @{
		ResourceGroupName = $resourceGroup
		Name = 'internal-lb'
		SKU = "Standard"
		Location = $location
		FrontendIpConfiguration = $feip
		BackendAddressPool = $bepoolInternal
		LoadBalancingRule = $rule1
		Probe = $internallbProbeSSH 
	}
	$internalLb = New-AzLoadBalancer @loadbalancer -Tag $tags
}
catch {
	Write-Host $_
}
Write-Output "6/11 Creating network Load-balancers .. Done!"

########################## Create NICs for VMs #################################
Write-Output "#######################################"
Write-Output "7/11 Creating network cards (NICs) ... "
Write-Output "#######################################"
#web
try {
	$webNics = @()
	for($i=1; $i -le $webTierVmCount ;$i++)
	{
		$webNics += New-AzNetworkInterface `
		  -Name $webTierVmNicName$i `
		  -ResourceGroupName $resourceGroup `
		  -Location $location `
		  -Subnet $vnet.Subnets[0] `
		  -IpConfigurationName "ipConfig1" `
		  -LoadBalancerBackendAddressPool $bepool -Tag $tags
	}
	#app
	$appNics = @()
	for($i=1; $i -le $appTierVmCount ;$i++)
	{
		$appNics += New-AzNetworkInterface `
		  -Name $appTierVmNicName$i `
		  -ResourceGroupName $resourceGroup `
		  -Location $location `
		  -Subnet $vnet.Subnets[1] `
		  -IpConfigurationName "ipConfig1" `
		  -LoadBalancerBackendAddressPool $bepoolInternal -Tag $tags
	}
	#DB
	$dbNics = @() 
	for($i=1; $i -le $databaseTierVmCount ;$i++)
	{
		$dbNics += New-AzNetworkInterface `
		  -Name $databaseTierVmNicName$i `
		  -ResourceGroupName $resourceGroup `
		  -Location $location `
		  -Subnet $vnet.Subnets[2] `
		  -IpConfigurationName "ipConfig1" -Tag $tags
	}

	#jumpbox
	$jumpNic = New-AzNetworkInterface `
		-Name $JumVmNicName `
		-ResourceGroupName $resourceGroup `
		-Location $location `
		-Subnet $vnet.Subnets[3] `
		-IpConfigurationName "ipConfig1" `
		-PublicIpAddress $JumpIPAdd -Tag $tags
}
catch {
	Write-Host $_
}
Write-Output "7/11 Creating network cards (NICs) ... Done!"

########################## Creating SSH keys #################################
ssh-keygen -m PEM -t rsa -b 4096
$digStorageAcc = Get-AzStorageAccount -ResourceGroupName $resourceGroup -Name $digStorageAccName

#Web VMs
########################## Create the VMs #################################
Write-Output "#####################################################"
Write-Output "8/11 Creating & configuring WEB virtual machines ... "
Write-Output "#####################################################"
##Bootstrapping web vms
try {
	$CloudinitFile="cloud-initWeb.txt" 
	$Bytes = [System.Text.Encoding]::Unicode.GetBytes((Get-Content -raw $CloudinitFile))
	$EncodedText=(Get-Content -raw $CloudinitFile)
	for($i=1; $i -le $webTierVmCount ;$i++)
	{
		$VMName = "$webTierVmName"+"-"+"$i"
		$OSDiskName = "$webTierVmName"+"-$i"+"_OSDisk"
		$ComputerName = "webserver$i"
		$OSDiskCaching = "ReadWrite"
		$OSCreateOption = "FromImage"

		$VMSize = "Standard_B1s"

		# Define a credential object
		$securePassword = ConvertTo-SecureString ' ' -AsPlainText -Force
		$cred = New-Object System.Management.Automation.PSCredential ("$adminUsername", $securePassword)

		# Create a virtual machine configuration
		$vmConfig = New-AzVMConfig `
		  -VMName "$VMName" -AvailabilitySetID $AvSet[0].Id `
		  -VMSize $VMSize | `
		Set-AzVMOperatingSystem `
		  -Linux `
		  -ComputerName $ComputerName `
		  -Credential $cred `
		  -CustomData $EncodedText `
		  -DisablePasswordAuthentication | `
		Set-AzVMSourceImage `
		  -PublisherName "OpenLogic" `
		  -Offer "CentOS" `
		  -Skus "7_9" `
		  -Version "latest" | `
		Add-AzVMNetworkInterface `
		  -Id $webNics[$i-1].Id |
		Set-AzVMBootDiagnostic -Enable `
			-ResourceGroupName $resourceGroup -StorageAccountName $digStorageAcc.StorageAccountName |
		Set-AzVMOSDisk -Name $OSDiskName -Caching $OSDiskCaching -CreateOption $OSCreateOption

		# Configure the SSH key
		$sshPublicKey = cat ~/.ssh/id_rsa.pub
		Add-AzVMSshPublicKey `
		  -VM $vmconfig `
		  -KeyData $sshPublicKey `
		  -Path ("/home/"+ $adminUsername + "/.ssh/authorized_keys")

		New-AzVM `
		  -ResourceGroupName $resourceGroup `
		  -Location $location -VM $vmConfig -Tag $tags
	  }
} 
catch {
	Write-Host $_
}
Write-Output "8/11 Creating & configuring WEB virtual machines ... Done!"

#App VMs
Write-Output "#####################################################"
Write-Output "9/11 Creating & configuring APP virtual machines ... "
Write-Output "#####################################################"
##Bootstrapping app vms
try {
	$CloudinitFile="cloud-initApp.txt" 
	$Bytes = [System.Text.Encoding]::Unicode.GetBytes((Get-Content -raw $CloudinitFile))
	$EncodedText=(Get-Content -raw $CloudinitFile)																													  
	for($i=1; $i -le $appTierVmCount ;$i++)
	{
		$VMName = "$appTierVmName"+"-"+"$i"
		$OSDiskName = "$appTierVmName"+"-$i"+"_OSDisk"
		$ComputerName = "appserver$i"
		$OSDiskCaching = "ReadWrite"
		$OSCreateOption = "FromImage"

		$VMSize = "Standard_B1s"

		# Define a credential object
		$securePassword = ConvertTo-SecureString ' ' -AsPlainText -Force
		$cred = New-Object System.Management.Automation.PSCredential ("$adminUsername", $securePassword)

		# Create a virtual machine configuration
		$vmConfig = New-AzVMConfig `
		  -VMName "$VMName" -AvailabilitySetID $AvSet[1].Id `
		  -VMSize $VMSize | `
		Set-AzVMOperatingSystem `
		  -Linux `
		  -ComputerName $ComputerName `
		  -Credential $cred `
		  -DisablePasswordAuthentication | `
		Set-AzVMSourceImage `
		  -PublisherName "OpenLogic" `
		  -Offer "CentOS" `
		  -Skus "7_9" `
		  -Version "latest" | `
		Add-AzVMNetworkInterface `
		  -Id $appNics[$i-1].Id |
		Set-AzVMBootDiagnostic -Enable `
			-ResourceGroupName $resourceGroup -StorageAccountName $digStorageAcc.StorageAccountName |
		Set-AzVMOSDisk -Name $OSDiskName -Caching $OSDiskCaching -CreateOption $OSCreateOption

		#Configure the SSH key
		$sshPublicKey = cat ~/.ssh/id_rsa.pub
		Add-AzVMSshPublicKey `
		  -VM $vmconfig `
		  -KeyData $sshPublicKey `
		  -Path ("/home/"+ $adminUsername + "/.ssh/authorized_keys")

		New-AzVM `
		  -ResourceGroupName $resourceGroup `
		  -Location $location -VM $vmConfig -Tag $tags
	  }
}
catch {
	Write-Host $_
}
Write-Output "9/11 Creating & configuring APP virtual machines ... Done!"

#Jump VM
Write-Output "################################################"
Write-Output "10/11 Creating the Jump server management VM... "
Write-Output "################################################"
try {
	$VMName = "$jumpVmName"
	$OSDiskName = "$jumpVmName"+"_OSDisk"
	$ComputerName = "jumpserver"
	$OSDiskCaching = "ReadWrite"
	$OSCreateOption = "FromImage"

	$VMSize = "Standard_B1s"

	#Define a credential object
	$securePassword = ConvertTo-SecureString ' ' -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential ("$adminUsername", $securePassword)

	#Create a virtual machine configuration
	$vmConfig = New-AzVMConfig `
		-VMName "$VMName" `
		-VMSize $VMSize | `
	Set-AzVMOperatingSystem `
		-Linux `
		-ComputerName $ComputerName `
		-Credential $cred `
		-DisablePasswordAuthentication | `
	Set-AzVMSourceImage `
		-PublisherName "OpenLogic" `
		-Offer "CentOS" `
		-Skus "7_9" `
		-Version "latest" | `
	Add-AzVMNetworkInterface `
		-Id $jumpNic.Id |
	Set-AzVMBootDiagnostic -Enable `
		-ResourceGroupName $resourceGroup -StorageAccountName $digStorageAcc.StorageAccountName |
	Set-AzVMOSDisk -Name $OSDiskName -Caching $OSDiskCaching -CreateOption $OSCreateOption

	#Configure the SSH key
	$sshPublicKey = cat ~/.ssh/id_rsa.pub
	Add-AzVMSshPublicKey `
		-VM $vmconfig `
		-KeyData $sshPublicKey `
		-Path ("/home/"+ $adminUsername + "/.ssh/authorized_keys")

	New-AzVM `
		-ResourceGroupName $resourceGroup `
		-Location $location -VM $vmConfig -Tag $tags
}
catch {
	Write-Host $_
}
Write-Output "10/11 Creating the Jump server management VM ... Done!"

#DB VMs (Azure SQL)
##Setup DB cluster HA
$dbsa = Get-AzStorageAccount -ResourceGroupName $resourceGroup -AccountName ($saName + "3")
# get storage account access key
$dbSaKeys = Get-AzStorageAccountKey -ResourceGroupName $resourceGroup -AccountName $dbsa.StorageAccountName
$dbSaPK =  ConvertTo-SecureString $dbSaKeys.Value[0] `
       -AsPlainText -Force 

#Create the SQL HA group
$clusterOperatorAccount = "hosam.badreldin@trojans.dsu.edu"
$domainFqdn = "domain.com"
$offer = "SQL2017-WS2016"
$skus = "Enterprise"
$VMSize = "Standard_B1s"
$ComputerName = "sqlserver"

#Define a credential object
$SecurePassword = Read-Host -AsSecureString 'Entger administrator password (aleast 8 characters, alphanumric, and special characters)'

$Cred = New-Object System.Management.Automation.PSCredential ($adminUsername, $securePassword)
for($i=1; $i -le $databaseTierVmCount ;$i++)
{
    # Create a virtual machine configuration
    $VMName = "$databaseTierVmName$i"
    $VMConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize |
       Set-AzVMOperatingSystem -Windows -ComputerName $ComputerName `
           -Credential $Cred -ProvisionVMAgent -EnableAutoUpdate |
       Set-AzVMSourceImage -PublisherName "MicrosoftSQLServer" `
           -Offer $offer -Skus $skus -Version "latest" |
       Add-AzVMNetworkInterface -Id $dbNics[$i-1].Id

    #Create the VM
    New-AzVM -ResourceGroupName $resourceGroup -Location $Location -VM $VMConfig  -Tag $tags  
}
#Enable DB vm as Azure SQL
for($i=1; $i -le $databaseTierVmCount ;$i++)
{
	$VMName = "$databaseTierVmName$i"
    $dbVm = Get-AzVM  -Name $VMName -ResourceGroupName $resourceGroup						 
																	 
        # Register SQL VM with 'Full' SQL IaaS agent
    $sqlVm = New-AzSqlVM -Name $VMName -ResourceGroupName $resourceGroup -Location $location `
      -LicenseType PAYG -SqlManagementType Full -Tag $tags
}