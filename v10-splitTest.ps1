Param(
      [parameter(Mandatory=$true)][string]$SourceFile, 
      [parameter(Mandatory=$true)][int]$numberOfSplits,
      [parameter(Mandatory=$true)][string]$EndLocation,
      [parameter(ParameterSetName='Scan', Mandatory=$false)][bool]$ScanFile=$false,
      [parameter(ParameterSetName='Scan', Mandatory=$false)][bool]$Recursive=$false
)

<#
Todo:
  Have Windows Defender scan split files = Done
  Delete chunk files after scanning = Done
  Detect AV (i.e.: Symantec Endpoint) = Done
  Use detected AV
  Recursive scanning
#>

Class scanner{
  
  static [String]$Symantec = "C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\DoScan.exe"
  [String]$selectedAV = ""

  [void]setAV($newAV){
      $this.selectedAV = $newAV
  }
  [String]getAV(){
      return $this.selectedAV
  }

}

function Convert-ByteArrayToHexString{
# Ref.: http://cyber-defense.sans.org/blog/2010/02/11/powershell-byte-array-hex-convert/
    [CmdletBinding()] Param (
    [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Byte[]] $ByteArray,
    [Parameter()] [Int] $Width = 4,
    [Parameter()] [String] $Delimiter = ",0x",
    [Parameter()] [String] $Prepend = "",
    [Parameter()] [Switch] $AddQuotes )
     
    if ($Width -lt 1) { $Width = 1 }
    if ($ByteArray.Length -eq 0) { Return }
    $FirstDelimiter = $Delimiter -Replace "^[\,\:\t]",""
    $From = 0
    $To = $Width - 1
    Do{
        $String = [System.BitConverter]::ToString($ByteArray[$From..$To])
        $String = $FirstDelimiter + ($String -replace "\-",$Delimiter)
        if ($AddQuotes) { $String = '"' + $String + '"' }
        if ($Prepend -ne "") { $String = $Prepend + $String }
        $String
        $From += $Width
        $To += $Width
    } While ($From -lt $ByteArray.Length)
}


#
# Just prints out basic info
#
function printHead($filePath, $size, $num, $chunkSize){
    $lastChunkSize = $($size - ($sizeOfChunks * ($numChunks - 1)))
    $headerMessage ="`n"
    $headerMessage+= "[+] In file = $filePath `n"
    $headerMessage+= "[+] Filesize is : $size bytes`n"
    $headerMessage+= "[+] Number of chunks: $($num)`n"
    $headerMessage+= "[+] Size of first $($num - 1): $([math]::Round($chunkSize))`n"
    $headerMessage+= "[+] Last chunk will be ~ $([math]::Round($lastChunkSize))`n"
    if($ScanFile){ 
        $antiVirusList = Get-AntivirusName
        if($antiVirusList.count -ne 1){ 
            Write-Host "[!] The following Anti-Virus have been detected:" -ForegroundColor yellow
            foreach ($av in $antiVirusList){
                Write-Host "[-]`t*" $av.displayName -ForegroundColor yellow
                if($($av.displayName) -like "Symantec Endpoint Protection"){
                    $constant.setAV($constant::Symantec)
                }
            }
            Write-host "`n"
            if(($constant.getAV()) -like '*Symantec*'){
                Write-Host "[!] Using Symantec Endpoint" -ForegroundColor green
                Write-host "[*] `t$($constant.getAV())" -ForegroundColor green
            }else{
                Write-Host "[!] Disabling scan feature" -ForegroundColor red
            }
        }
        if($Recursive){
            $headerMessage += "[!] Scan recursive: $Recursive`n"
        }
    }
    return $headerMessage
}


#
# Scan file using default Windows Defender install
#
function scanFolder($file){
  #
  # Start-MpScan -ScanType CustomScan -ScanPath "C:\Users\loneferret\Desktop\catchFiles\"
  #
  $fileExist = Test-Path "$file"
  $result = 0
  if($fileExist){
        Write-Host -NoNewline "[+] Checking file..."
        if(!$($constant.getAV())){
            Start-MpScan -ScanType CustomScan -ScanPath "$file"   # Will need to adjust for other AVs
        }else{
            #Write-Host $constant.getAV() $file
            &  $constant.getAV() $file
        }
        sleep(10)
        $fileExist = Test-Path "$file"  
        if($fileExist){
                Write-Host "File is clean..."
            }else{
                Write-Host "`n"
                Write-Host "[!] File contains signature..."
                $result = 1
        }
  }
  return $result
}

#
# Find installed anti-virus
#
function Get-AntivirusName { 
    # Author  :  Aman Dhally
    [cmdletBinding()]     
    param ( 
        [string]$ComputerName = "$env:computername", 
        $Credential 
    ) 
     BEGIN { 
            # Setting WMI query in a variable 
            $wmiQuery = "SELECT * FROM AntiVirusProduct" 
 
    } PROCESS { 
            # doing getting wmi 
            $AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters # -ErrorVariable myError -ErrorAction 'SilentlyContinue'    
            #foreach ($av in $AntivirusProduct){         
            #    Write-host $av.displayName -ForegroundColor Cyan
            #}
    } END { return $AntivirusProduct } 
}


function chunkSplit($counter,$newFilePath,$i,$chunkSize){
  # 
    $newFilename = "chunk`_$($counter).bin"
    #[System.io.file]::WriteAllBytes("$newFilePath\$newFilename", $stream[0..$($counter * $sizeOfChunks)])
    [System.io.file]::WriteAllBytes("$newFilePath\$newFilename", $stream[0..$($chunkSize)])


    $startChunk = [math]::Round([string]$($i * $sizeOfChunks))
    $endChunk = [math]::Round($(($counter) * $sizeOfChunks))
    if([string]::IsNullOrEmpty($startChunk)) {$startChunk = "0"}
    Write-Host "[-] chunk # $counter`t $startChunk -- $endChunk`t: $newFilename"
    if($ScanFile -And ($antiVirus.count -ne 1)){
        if($(scanFolder "$newFilePath\$newFilename")){
            [System.io.file]::WriteAllBytes("$newFilePath\$([math]::Round($chunkSize))`_$newFilename", $stream[0..$(($i+1) * $sizeOfChunks)])

            # Writting text file of hext dump
            $hexTextFile = Convert-ByteArrayToHexString $($stream[0..$(($i+1) * $sizeOfChunks)])
            [System.io.file]::WriteAllText("$newFilePath\$startChunk-$endChunk`_$newFilename.text",$hexTextFile)

            Write-Host "[+] Signature is between bytes $startChunk `& $endChunk"
            # Write-Host "[+] New file created: $([math]::Round($chunkSize))`_$newFilename"
            Write-Host "[+] New file created: $startChunk-$endChunk`_$newFilename"
            Write-Host "[!] Deleting chunk files...`n"
            Remove-Item $newFilePath\chunk*.bin -Confirm:$false
            if(!$Recursive){
                exit
            }else{
                $Recursive = $false
                Write-Host "`n[!] Submitting new file... $([math]::Round($chunkSize))`_$newFilename"
                sleep(10)
                [System.io.file]::WriteAllBytes("$newFilePath\$([math]::Round($chunkSize))`_$newFilename", $stream[0..$(($i+1) * $sizeOfChunks)])
                splitByChunk "$newFilePath\$([math]::Round($chunkSize))`_$newFilename" "2"
            }
        }
    }
}


#
# @params [string] inFile : Full path to file to split
# @params [int] numChunks : Number of pieces the file is broken into
#
function splitByChunk([string]$inFile, [int]$numChunks){

  $stream = [System.IO.File]::ReadAllBytes($inFile)
  $size = $stream.Length
  $newFilePath = $EndLocation
  $sizeOfChunks = ($size / $numChunks)


  $banner = printHead $inFile $size $numChunks $sizeOfChunks 
  Write-Host $banner

  $startPosition = 0
  $endPosition = 0
  $counter = 0

  $symantecAV = New-Object scanner
  echo $symantecAV::symantecPATH

  for ($i -eq 0; $i -lt $numChunks; $i++){
      $counter++
      $chunk = $($counter * $sizeOfChunks)
      if($counter -eq ($numChunks)){  # Last chunk, which is essentially a copy of the file
          chunkSplit $counter $newFilePath $i $size
          exit
      }
      chunkSplit $counter $newFilePath $i $chunk
  }

}
$constant = New-Object scanner
splitByChunk $SourceFile $($numberOfSplits)