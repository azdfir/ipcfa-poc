<#
.SYNOPSIS
    Creates a forenic environment in Azure subscription (VM from shared gallery, Vault, Immutable storage, file share)

.DESCRIPTION
    This is designed to be run from Azure cloud shell (PowerShell).
	This will create 1 vm, 1 key vault, 1 storage and storage blob, 1 shared file 
  
.EXAMPLE
  ./azDF_DFIREnvPrep.ps1 -DFIRtenant 79ebb2ce-3b99-4ccd-850d-8de98f5e9a39 -DFIRRG DFIR -DFIRgallery WinGallary -DFIRimage winDFIR -DFIRimageVer 0.0.1
#>

param (
    # The remote subscription for tenant of the image gallery
    [Parameter(Mandatory = $true)]
    [string]
    $DFIRtenant,
    # The remote RG of the image gallery
    [Parameter(Mandatory = $true)]
    [string]
    $DFIRRG,	
	# The remote shared gallery
    [Parameter(Mandatory = $true)]
    [string]
    $DFIRgallery,	
	# The remote image
    [Parameter(Mandatory = $true)]
    [string]
    $DFIRimage,
	# The remote image version
    [Parameter(Mandatory = $true)]
    [string]
	$DFIRimageVer
)

# connecting to DFIR subscription
$connectiondfirtenant = Connect-AzAccount -Tenant $DFIRtenant -UseDeviceAuthentication

# Define variables
$ResourceGroup = "zoolsec" 
$Location = "eastus"
$vNetName = "zoolsecVNET"
$AddressSpace = "10.10.10.0/24"    # Base Format : 10.10.0.0/16
$SubnetIPAddress = "10.10.10.0/27" # Base Format : 10.10.10.0/24
$SubnetName = "zoolsecSubnet"
$nsgName = "zSec01"
$vmName = "dfir-vm"
$cxt=Get-AzContext
$uniqueStartString = $cxt.Account.Id.split('@')[0].ToLower()
$StorageAccount = ("sa"+$uniqueStartString+"zoolsecstr")# This Storage Account Name must be unique.
if($StorageAccount.Length -gt 23)
{
    $StorageAccount = $StorageAccount.Substring(0,23) 
}
$ContainerName =  "zoolsecimmutable"      # Immutable Container Name
$AzKeyVault = $uniqueStartString+"zoolSecVault"      # Azure Key Vault Name
$ShareName = "zoolSecTempfile"       # Storage Account TEMP Share Name

# Create Resource Groups and Storage Account for Diagnostics
New-AzResourceGroup -Name $ResourceGroup -Location $Location
$StorageAccountObj = New-AzStorageAccount -Name $StorageAccount -ResourceGroupName $ResourceGroup -Location $Location -SkuName Standard_LRS

# Create Network Security Group
$nsgRuleVMAccess = New-AzNetworkSecurityRuleConfig -Name 'allow-vm-access' -Protocol Tcp -Direction Inbound -Priority 100 -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 22,3389 -Access Allow
$nsg = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroup -Location $location -Name $nsgName -SecurityRules $nsgRuleVMAccess

# Create Virtual Network and Subnet
$tierSubnet = New-AzVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix $SubnetIPAddress `
    -NetworkSecurityGroup $nsg
$vNetwork = New-AzVirtualNetwork -ResourceGroupName $ResourceGroup -Name $vNetName -AddressPrefix $AddressSpace -Location $location -Subnet $tierSubnet
Set-AzVirtualNetwork -VirtualNetwork $vNetwork

# Define Variables needed for Virtual Machine
$vNet       = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroup -Name $vNetName
$Subnet     = Get-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $vNet
$nsg        = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroup -Name $NsgName


# Create Admin Credentials
$adminUsername = Read-Host 'Admin username'
$adminPassword = Read-Host -AsSecureString 'Admin password with least 12 characters'
$adminCreds    = New-Object PSCredential $adminUsername, $adminPassword

$pipName    = "$vmName-pip" 
$nicName    = "$vmName-nic"

# Create a public IP and NIC
$pip = New-AzPublicIpAddress -Name $pipName -ResourceGroupName $ResourceGroup -Location $location -AllocationMethod Static 
$nic = New-AzNetworkInterface -Name $nicName -ResourceGroupName $ResourceGroup -Location $location -SubnetId $Subnet.Id -PublicIpAddressId $pip.Id -NetworkSecurityGroupId $nsg.Id

$vmName = "myVMfromImage2"
$vmSize = "Standard_B1s"
     
# Set a variable for the image version in Tenant 1 using the full image ID of the shared image version
$image = "/subscriptions/$DFIRtenant/resourceGroups/$DFIRRG/providers/Microsoft.Compute/galleries/$DFIRgallery/images/$DFIRimage/versions/$DFIRimageVer"

$pubName	= "MicrosoftWindowsDesktop"
$offerName	= "Windows-10"
$skuName	= "20h1-pro"

# Create a virtual machine configuration using the $image variable to specify the shared image
$vmConfig = New-AzVMConfig -VMName $vmName -VMSize $vmSize | `
Set-AzVMOperatingSystem  -Windows -ComputerName $vmName -Credential $adminCreds | `
Set-AzVMPlan -Product $offerName -Publisher $pubName -Name $skuName | `
Set-AzVMSourceImage -Id $image | `
#-PublisherName $pubName -Offer $offerName -Skus $skuName  -Version "0.0.1" -DefaultProfile $connectiondfirtenant | `
Add-AzVMNetworkInterface -Id $nic.Id

#-PublisherName $pubName -Offer $offerName -Skus $skuName  -Version "0.0.1" `

# Create a virtual machine
New-AzVM -ResourceGroupName $resourceGroup -Location $location -VM $vmConfig

#Register-AzResourceProvider -ProviderNamespace "Microsoft.Storage"
$StorageAccountObj = Get-AzStorageAccount -Name $StorageAccount -ResourceGroup $ResourceGroup
# Create a New container
$Container = New-AzureStorageContainer -Name $ContainerName  `
-Context $StorageAccountObj.Context

# Enabling immutability + allow protected append blobs writes
Set-AzureRmStorageContainerImmutabilityPolicy -ResourceGroupName $ResourceGroup `
-StorageAccountName $StorageAccount -ContainerName $ContainerName -ImmutabilityPeriod 10 `
-AllowProtectedAppendWrite $true

# Azure Key Vault
New-AzKeyVault -Name $AzKeyVault -ResourceGroupName $ResourceGroup -Location $Location -EnabledForDiskEncryption -Sku Standard

# Create TEMP Share
New-AzRmStorageShare -ResourceGroupName $ResourceGroup -StorageAccountName $StorageAccount -Name $ShareName -AccessTier TransactionOptimized -QuotaGiB 1024 | Out-Null