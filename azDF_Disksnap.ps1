<#
.SYNOPSIS
    Performs a virtual machines disk aquisation in Azure Cloud 

.DESCRIPTION
    This script will create disk snapshots for targetted VMs. 
    It will copy images to immutable storage, and take a SHA-256 hash and storing the results in your Key Vault.
	
.EXAMPLE
	./azDF_Disksnap.ps1  -ResourceGroupName zoolsecRG -VirtualMachineName zweb-vm1 -OsType windows
#>

param (
    # The Resource Group for the target Virtual Machine
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,

    # The name of the target Virtual Machine
    [Parameter(Mandatory = $true)]
    [string]
    $VirtualMachineName,

    # The name of the target OS
    [Parameter(Mandatory = $true)]
    [string]
    $OsType
)

$ErrorActionPreference = 'Stop'

# Destination varibales
$destRGName = $ResourceGroupName                           # The Resource Group containing the storage account being copied to
$destSAblob = $saName                          # The name of the storage account for BLOB
$destSAfile = $saName                          # The name of the storage account for FILE
$destTempShare = $tempFileShare                        # The temporary file share mounted on the hybrid worker
$destSAContainer = $contName                      # The name of the container within the storage account
$destKV = $kvName                              # The name of the key-vault to store a copy of the BEK in the dest subscription

$targetWindowsDir = "Z:\$destTempShare"               # The mapping path to the share that will contain the disk and its hash
$targetLinuxDir = "/mnt/$destSAfile/$destTempShare"       # The name of directory in which file share is mounted 
$snapshotPrefix = (Get-Date).toString('yyyyMMddHHmm') # The name of the snapshot to be created

############################# Snapshot the OS disk of target VM ##############################
Write-Output "#################################"
Write-Output "Snapshot the OS Disk of target VM"
Write-Output "#################################"

Set-AzContext
$vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VirtualMachineName

$disk = Get-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $vm.StorageProfile.OsDisk.Name
$snapshot = New-AzSnapshotConfig -SourceUri $disk.Id -CreateOption Copy -Location $vm.Location
$snapshotName = $snapshotPrefix + "-" + $disk.name.Replace("_","-")
New-AzSnapshot -ResourceGroupName $ResourceGroupName -Snapshot $snapshot -SnapshotName $snapshotname


##################### Copy the OS snapshot from source to file share and blob container ########################
Write-Output "#######################"
Write-Output "Acquiring disk snapshot"
Write-Output "#######################"

$snapSasUrl = Grant-AzSnapshotAccess -ResourceGroupName $ResourceGroupName -SnapshotName $snapshotName -DurationInSecond 72000 -Access Read
Set-AzContext
$targetStorageContextBlob = (Get-AzStorageAccount -ResourceGroupName $destRGName -Name $destSAblob).Context
$targetStorageContextFile = (Get-AzStorageAccount -ResourceGroupName $destRGName -Name $destSAfile).Context

Write-Output "Start Copying Blob $SnapshotName"
Start-AzStorageBlobCopy -AbsoluteUri $snapSasUrl.AccessSAS -DestContainer $destSAContainer -DestContext $targetStorageContextBlob -DestBlob "$SnapshotName.vhd" -Force

Write-Output "Start Copying Fileshare"
Start-AzStorageFileCopy -AbsoluteUri $snapSasUrl.AccessSAS -DestShareName $destTempShare -DestContext $targetStorageContextFile -DestFilePath $SnapshotName -Force

Write-Output "Waiting Fileshare Copy End"
Get-AzStorageFileCopyState -Context $targetStorageContextFile -ShareName $destTempShare -FilePath $SnapshotName -WaitForComplete
if($OsType.ToLower().Contains("windows")){
    #Windows hash
    $imagepath = ".\.bash_history"#"$targetWindowsDir\$snapshotName"    
    Write-Output "Calculating hash value for $imagepath"
    Get-ChildItem "$imagepath" | Select-Object -Expand FullName | ForEach-Object{Write-Output $_}
    $hash = (Get-FileHash $imagepath -Algorithm SHA256).Hash
    Write-Output "SHA-256 calculated: $hash"
}
else{
    # Linux hash
    $imagepath = "$targetLinuxDir/$snapshotName"    
    Write-Output "Calculating hash value for $imagepath"
    $hashfull = Invoke-Expression -Command "sha256sum $imagepath" 
    $hash = $hashfull.split(" ")[0]
    Write-Output "CSHA-256 calculated: $hash"
}

#################### Copy the OS BEK to the SOC Key Vault  ###################################
$BEKurl = $disk.EncryptionSettingsCollection.EncryptionSettings.DiskEncryptionKey.SecretUrl
Write-Output "#################################"
Write-Output "OS Disk Encryption Secret URL: $BEKurl"
Write-Output "#################################"
if ($BEKurl) {
    $sourcekv = $BEKurl.Split("/")
    $BEK = Get-AzKeyVaultSecret -VaultName  $sourcekv[2].split(".")[0] -Name $sourcekv[4] -Version $sourcekv[5]
    Write-Output "Key value: $BEK"
    Set-AzContext
    Set-AzKeyVaultSecret -VaultName $destKV -Name $snapshotName -SecretValue $BEK.SecretValue -ContentType "BEK" -Tag $BEK.Tags
}

######## Copy the OS disk hash value in key vault and delete disk in file share ##################
Write-Output "#################################"
Write-Output "OS disk - Put hash value in Key Vault"
Write-Output "#################################"
$secret = ConvertTo-SecureString -String $hash -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName $destKV -Name "$SnapshotName-sha256" -SecretValue $secret -ContentType "text/plain"
Set-AzContext
$targetStorageContextFile = (Get-AzStorageAccount -ResourceGroupName $destRGShare -Name $destSAfile).Context
Remove-AzStorageFile -ShareName $destTempShare -Path $SnapshotName -Context $targetStorageContextFile


############################ Snapshot the data disks, store hash and BEK #####################
$dsnapshotList = @()

foreach ($dataDisk in $vm.StorageProfile.DataDisks) {
    $ddisk = Get-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $dataDisk.Name
    $dsnapshot = New-AzSnapshotConfig -SourceUri $ddisk.Id -CreateOption Copy -Location $vm.Location
    $dsnapshotName = $snapshotPrefix + "-" + $ddisk.name.Replace("_","-")
    $dsnapshotList += $dsnapshotName
    Write-Output "Snapshot data disk name: $dsnapshotName"
    New-AzSnapshot -ResourceGroupName $ResourceGroupName -Snapshot $dsnapshot -SnapshotName $dsnapshotName
        
    Write-Output "#################################"
    Write-Output "Copy the Data Disk $dsnapshotName snapshot from source to blob container"
    Write-Output "#################################"

    $dsnapSasUrl = Grant-AzSnapshotAccess -ResourceGroupName $ResourceGroupName -SnapshotName $dsnapshotName -DurationInSecond 72000 -Access Read
    $targetStorageContextBlob = (Get-AzStorageAccount -ResourceGroupName $destRGName -Name $destSABlob).Context
    $targetStorageContextFile = (Get-AzStorageAccount -ResourceGroupName $destRGName -Name $destSAFile).Context

    Write-Output "Start Copying Blob $dsnapshotName"
    Start-AzStorageBlobCopy -AbsoluteUri $dsnapSasUrl.AccessSAS -DestContainer $destSAContainer -DestContext $targetStorageContextBlob -DestBlob "$dsnapshotName.vhd" -Force

    Write-Output "Start Copying Fileshare"
    Start-AzStorageFileCopy -AbsoluteUri $dsnapSasUrl.AccessSAS -DestShareName $destTempShare -DestContext $targetStorageContextFile -DestFilePath $dsnapshotName  -Force
        
    Write-Output "Waiting Fileshare Copy End"
    Get-AzStorageFileCopyState -Context $targetStorageContextFile -ShareName $destTempShare -FilePath $dsnapshotName -WaitForComplete
    if($OsType.ToLower().Contains("window")){            
    $dimagepath = "$targetWindowsDir\$dsnapshotName"
    Write-Output "Start Calculating HASH for $dimagepath"
    Get-ChildItem "$dimagepath" | Select-Object -Expand FullName | ForEach-Object{Write-Output $_}
    $hash = (Get-FileHash $imagepath -Algorithm SHA256).Hash
    }
    else
    {
        $dimagepath = "$targetLinuxDir/$dsnapshotName"
        Write-Output "Start Calculating HASH for $dimagepath"
        
        $dhashfull = Invoke-Expression -Command "sha256sum $dimagepath"
        $dhash = $dhashfull.split(" ")[0]
    }

    Write-Output "Computed SHA-256: $dhash"
        
        
    $BEKurl = $ddisk.EncryptionSettingsCollection.EncryptionSettings.DiskEncryptionKey.SecretUrl
    Write-Output "#################################"
    Write-Output "Disk Encryption Secret URL: $BEKurl"
    Write-Output "#################################"
    if ($BEKurl) {
        $sourcekv = $BEKurl.Split("/")
        $BEK = Get-AzKeyVaultSecret -VaultName  $sourcekv[2].split(".")[0] -Name $sourcekv[4] -Version $sourcekv[5]
        Write-Output "Key value: $BEK"
        Write-Output "Secret name: $dsnapshotName"
        Set-AzKeyVaultSecret -VaultName $destKV -Name $dsnapshotName -SecretValue $BEK.SecretValue -ContentType "BEK" -Tag $BEK.Tags
    }
    else {
        Write-Output "Disk not encrypted"
    }

    Write-Output "#################################"
    Write-Output "Data disk - Put hash value in Key Vault"
    Write-Output "#################################"
    $Secret = ConvertTo-SecureString -String $dhash -AsPlainText -Force
    Set-AzKeyVaultSecret -VaultName $destKV -Name "$dsnapshotName-sha256" -SecretValue $Secret -ContentType "text/plain"
    $targetStorageContextFile = (Get-AzStorageAccount -ResourceGroupName $destRGShare -Name $destSAfile).Context
    Remove-AzStorageFile -ShareName $destTempShare -Path $dsnapshotName -Context $targetStorageContextFile
}

################################## Delete all source snapshots ###############################
Get-AzStorageBlobCopyState -Blob "$snapshotName.vhd" -Container $destSAContainer -Context $targetStorageContextBlob -WaitForComplete
foreach ($dsnapshotName in $dsnapshotList) {
    Get-AzStorageBlobCopyState -Blob "$dsnapshotName.vhd" -Container $destSAContainer -Context $targetStorageContextBlob -WaitForComplete
}

Revoke-AzSnapshotAccess -ResourceGroupName $ResourceGroupName -SnapshotName $snapshotName
Remove-AzSnapshot -ResourceGroupName $ResourceGroupName -SnapshotName $snapshotname -Force
foreach ($dsnapshotName in $dsnapshotList) {
    Revoke-AzSnapshotAccess -ResourceGroupName $ResourceGroupName -SnapshotName $dsnapshotName
    Remove-AzSnapshot -ResourceGroupName $ResourceGroupName -SnapshotName $dsnapshotname -Force
}