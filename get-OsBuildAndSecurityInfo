$colItems = Get-ChildItem $startFolder -force | Where-Object  {!$_.LinkType -and ($_.PSIsContainer -eq $true) }| Sort-Object
$objs = @()
foreach ($i in $colItems) {
    write-host $i.name
    try {
        $subFolderItems = Get-ChildItem $i.FullName -recurse -force -ErrorAction stop | Where-Object { $_.PSIsContainer -eq $false } | Measure-Object -property Length -sum  | Select-Object Sum 
        $o = [pscustomobject]@{
            folder = $i.FullName
            SizeMB = ($subFolderItems.sum ) / 1MB #+ $i.Length
            MeasuredProperly =$true
        }
    }
    catch  {
        Write-Host "*** May need to run asAdministrator:  could not get size of: $($i.name)" -ForegroundColor Yellow
        $o = [pscustomobject]@{
            folder = $i.FullName
            SizeMB = 0 #+ $i.Length
            MeasuredProperly =$false
        }
    }
    $objs +=$o
}
$objs | sort-Object -property SizeMB -descending
