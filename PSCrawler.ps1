param (
    [string[]]$path = @("C:\"),
    [string[]]$name,
    [string]$hash,
    [long]$size,
    [string]$algorithm = "md5",
    [string]$target = $(Throw "No endpoint specified for results."),
    [long]$query = $(Throw "No query ID specified for results.")
)

function findByName($file) {
    if ($name) {
        ForEach ($fileName in $name) {
            if ($file.Name -like $fileName) {
                createObject $file
            }
        }
    }
}

function findByHash($file) {
    if ((Get-FileHash -Path $_.FullName -Algorithm $algorithm).Hash -eq $hash -and $hash) {
        createObject $file
    }
}

function findBySize($file) {
    if ($file.Length -eq $size -and $size) {
        createObject $file
    }
}

function findByNameAndHash($file) {
    if ($name -and $hash) {
        ForEach ($fileName in $name) {    
            if ($file.Name -like $fileName -and (Get-FileHash -Path $_.FullName -Algorithm $algorithm).Hash -eq $hash) {
                createObject $file
            }
        }
    }
}

function findByNameAndSize($file) {
    if ($name -and $size) {
        ForEach ($fileName in $name) {    
            if ($file.Name -like $fileName -and $file.Length -eq $size) {
                createObject $file
            }
        }
    }
}

function findByHashAndSize($file) {
    if ($hash -and $size) {
        if ($file.Length -eq $size -and (Get-FileHash -Path $_.FullName -Algorithm $algorithm).Hash -eq $hash) {
            createObject $file
        }
    }
}

function findByEverything($file) {
    if ($name -and $hash -and $size) {
        ForEach ($fileName in $name) {    
            if ($file.Name -like $fileName -and $file.Length -eq $size -and (Get-FileHash -Path $_.FullName -algorithm $algorithm).Hash -eq $hash) {
                createObject $file
            }
        }
    }
}

function createObject($file) {
    $object = New-Object PSObject
    Add-Member -InputObject $object -MemberType NoteProperty -Name Name -Value $file.Name
    Add-Member -InputObject $object -MemberType NoteProperty -Name BaseName -Value $file.BaseName    
    Add-Member -InputObject $object -MemberType NoteProperty -Name FullName -Value $file.FullName    
    Add-Member -InputObject $object -MemberType NoteProperty -Name DirectoryName -Value $file.DirectoryName

    Add-Member -InputObject $object -MemberType NoteProperty -Name Hostname -Value $env:computername
    Add-Member -InputObject $object -MemberType NoteProperty -Name IP -Value $computerInfo.IPV4Address.IPAddressToString

    Add-Member -InputObject $object -MemberType NoteProperty -Name CreationTime -Value $file.CreationTime
    Add-Member -InputObject $object -MemberType NoteProperty -Name LastAccessTime -Value $file.LastAccessTime
    Add-Member -InputObject $object -MemberType NoteProperty -Name LastWriteTime -Value $file.LastWriteTime
    Add-Member -InputObject $object -MemberType NoteProperty -Name Access -Value $file.Mode

    $folderObject = New-Object PSObject
    $dirDetails = Get-Item $file.Directory

    Add-Member -InputObject $folderObject -MemberType NoteProperty -Name Name -Value $dirDetails.FullName
    Add-Member -InputObject $folderObject -MemberType NoteProperty -Name Access -Value $dirDetails.Mode

    Add-Member -InputObject $folderObject -MemberType NoteProperty -Name CreationTime -Value $dirDetails.CreationTime
    Add-Member -InputObject $folderObject -MemberType NoteProperty -Name LastAccessTime -Value $dirDetails.LastAccessTime
    Add-Member -InputObject $folderObject -MemberType NoteProperty -Name LastWriteTime -Value $dirDetails.LastWriteTime

    Add-Member -InputObject $object -MemberType NoteProperty -Name Directory -Value $folderObject

    Add-Member -InputObject $object -MemberType NoteProperty -Name QueryID -Value $query

    $json = "{`"Name`": `"" + $file.Name + "`", `"BaseName`":`"" + $file.BaseName + "`", `"FullName`":`""+ $file.FullName + "`", `"DirectoryName`": `"" + $file.DirectoryName + 
    "`", `"Hostname`": `"" + $env:computername + "`",`"IP`":`"" + $computerInfo.IPV4Address.IPAddressToString + "`", `"CreationTime`":`"" + $file.CreationTime + 
    "`", `"LastAccessTime`": `"" + $file.LastAccessTime + "`",`"LastWriteTime`": `"" + $file.LastWriteTime + "`", `"Access`": `"" + $file.Mode + 
    "`", `"Directory`":{`"Name`":`"" + $dirDetails.FullName + "`",`"Access`":`"" + $dirDetails.Mode + "`",`"CreationTime`":`"" + $dirDetails.CreationTime + 
    "`",`"LastAccessTime`":`"" + $dirDetails.LastAccessTime + "`" ,`"LastWriteTime`":`"" + $dirDetails.LastWriteTime + "`"},`"QueryID`":" + $query + "}"

    $jsonProcess = $json.Replace("\", "\\")
    $jsonProcessEscape = $jsonProcess.Replace("`"", "\```"")

    $script = ".\curl.exe  $target -H `"Accept: application/json`" -H `"Content-Type: application/json`" -X POST -d `"$jsonProcessEscape`""
    iex $script
}

function createObjectFromPath($folder) {
    $object = New-Object PSObject
    $dirDetails = Get-Item $folder

    Add-Member -InputObject $object -MemberType NoteProperty -Name Name -Value $dirDetails.FullName
    Add-Member -InputObject $object -MemberType NoteProperty -Name Access -Value $dirDetails.Mode

    Add-Member -InputObject $object -MemberType NoteProperty -Name CreationTime -Value $dirDetails.CreationTime
    Add-Member -InputObject $object -MemberType NoteProperty -Name LastAccessTime -Value $dirDetails.LastAccessTime
    Add-Member -InputObject $object -MemberType NoteProperty -Name LastWriteTime -Value $dirDetails.LastWriteTime

    Add-Member -InputObject $object -MemberType NoteProperty -Name Hostname -Value $env:computername
    Add-Member -InputObject $object -MemberType NoteProperty -Name IP -Value $computerInfo.IPV4Address.IPAddressToString

    Add-Member -InputObject $object -MemberType NoteProperty -Name QueryID -Value $query

    $json = "{`"Name`": `"" + $object.Name + "`", `"Access`": `"" + $object.Access + "`", `"CreationTime`": `"" + $object.CreationTime + "`", `"LastAccessTime`": `"" + $object.LastAccessTime + "`", `"LastWriteTime`": `"" + $object.LastWriteTime + "`", `"Hostname`": `"" + $object.Hostname + "`", `"IP`": `"" + $object.IP + "`", `"QueryId`": " + $query + "}"
    $jsonProcess = $json.Replace("\", "\\")
    $jsonProcessEscape = $jsonProcess.Replace("`"", "\```"")

    $script = ".\curl.exe  $target -H `"Accept: application/json`" -H `"Content-Type: application/json`" -X POST -d `"$jsonProcessEscape`""
    iex $script
}

$computerInfo = Test-Connection -ComputerName (hostname) -Count 1

if (!$name -and !$hash -and !$size) {
    if ($path) {
        ForEach ($dir in $path) {
            if(Test-Path $dir) {
                createObjectFromPath $dir
            }
        }
    }
}
else {
    ForEach ($dir in $path) {
        if (Test-Path $dir) {
            Get-ChildItem -Force -Path $dir -File -Recurse | ForEach-Object {
                if ($name -and !$hash -and !$size) {
                    findByName $_
                }
                elseif (!$name -and $hash -and !$size) {
                    findByHash $_
                }
                elseif (!$name -and !$hash -and $size) {
                    findBySize $_
                }
                elseif ($name -and $hash -and !$size) {
                    findByNameAndHash $_
                }
                elseif ($name -and !$hash -and $size) {
                    findByNameAndSize $_
                }
                elseif (!$name -and $hash -and $size) {
                    findByHashAndSize $_
                }
                elseif ($name -and $hash -and $size) {
                    findByEverything $_
                }
                else {
                    Write-Error "Arguments invalid."
                }
            }
        }
    }
}