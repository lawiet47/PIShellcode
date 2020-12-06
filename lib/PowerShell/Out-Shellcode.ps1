Param (
    [Parameter(Position = 0, Mandatory = $True)]
    [String]
    $InputExe,

    [Parameter(Position = 1, Mandatory = $True)]
    [ValidateScript({ Test-Path $_ })]
    [String]
    $ProjectDir,

    [Parameter(Position = 3, Mandatory = $True)]
    [String]
    $OutputFile
)

$GetPEHeader = Join-Path $ProjectDir Get-PEHeader.ps1

. $GetPEHeader

$PE = Get-PEHeader $InputExe -GetSectionData
$TextSection = $PE.SectionHeaders | Where-Object { $_.Name -eq '.text' }


Write-Host "Text Section length: 0x$(($TextSection.VirtualSize + 1).ToString('X4'))"

[IO.File]::WriteAllBytes($OutputFile, $TextSection.RawData[0..$TextSection.VirtualSize])
