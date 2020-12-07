<#

.EXAMPLE
    ./powershell -exec bypass XOR_Shellcode.ps1 C:\shellcode.bin C:\encrypted.bin

.SYNOPSIS
    .
#>

param (
    [Parameter(Mandatory=$true)]
    [string] $shellcode_file, #First File
    [Parameter(Mandatory=$true)]
    [string] $out #Output File
) #end param

 

$shell_bytes = [System.IO.File]::ReadAllBytes("$shellcode_file") 
$xor_key = 0x32, 0x47, 0x68, 0x84, 0x59, 0x91, 0x34, 0x17, 0x58, 0x13, 0x77, 0x69 ,0x09 ,0x11, 0x19, 0x94
 


for($i=0; $i -lt $shell_bytes.Length ; $i++)
{
    $shell_bytes[$i] = $shell_bytes[$i] -bxor $xor_key[$i % $xor_key.Length]
}
 
[System.IO.File]::WriteAllBytes("$out", $shell_bytes)

write-host "[*] Encrypted file saved to "$out"";