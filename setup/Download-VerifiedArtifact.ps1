param(
    [Parameter(Mandatory = $true)][string]$Uri,
    [Parameter(Mandatory = $true)][string]$Destination,
    [Parameter(Mandatory = $true)][long]$Length,
    [Parameter(Mandatory = $true)][string]$Sha256,
    [int]$ChunkMiB = 8,
    [int]$Parallelism = 6
)

$ErrorActionPreference = 'Stop'
$taskDestination = [System.IO.Path]::GetFullPath($Destination)
$taskPartsDir = $taskDestination + '.parts'
New-Item -ItemType Directory -Path $taskPartsDir -Force | Out-Null
$taskChunkSize = [long]$ChunkMiB * 1MB
$taskChunkCount = [int][math]::Ceiling($Length / [double]$taskChunkSize)
$taskPending = New-Object 'System.Collections.Generic.Queue[int]'
$taskActive = New-Object System.Collections.ArrayList
$taskCompleted = 0

for ($taskIndex = 0; $taskIndex -lt $taskChunkCount; $taskIndex++) {
    $taskPartPath = Join-Path $taskPartsDir ('{0:D4}.part' -f $taskIndex)
    $taskPartLength = [math]::Min($taskChunkSize, $Length - $taskIndex * $taskChunkSize)
    if ((Test-Path -LiteralPath $taskPartPath) -and (Get-Item -LiteralPath $taskPartPath).Length -eq $taskPartLength) {
        $taskCompleted++
    } else {
        $taskPending.Enqueue($taskIndex)
    }
}

while ($taskPending.Count -gt 0 -or $taskActive.Count -gt 0) {
    while ($taskPending.Count -gt 0 -and $taskActive.Count -lt $Parallelism) {
        $taskIndex = $taskPending.Dequeue()
        $taskStart = [long]$taskIndex * $taskChunkSize
        $taskEnd = [math]::Min($taskStart + $taskChunkSize - 1, $Length - 1)
        $taskPartPath = Join-Path $taskPartsDir ('{0:D4}.part' -f $taskIndex)
        $taskErrorPath = Join-Path $taskPartsDir ('{0:D4}.stderr.log' -f $taskIndex)
        $taskOutputPath = Join-Path $taskPartsDir ('{0:D4}.stdout.log' -f $taskIndex)
        $taskProcess = Start-Process -FilePath 'curl.exe' -ArgumentList @(
            '--ipv4', '--http1.1', '--fail', '--location', '--silent', '--show-error',
            '--connect-timeout', '15', '--max-time', '180', '--retry', '3', '--retry-delay', '1',
            '--range', "$taskStart-$taskEnd", '--output', $taskPartPath, $Uri
        ) -WindowStyle Hidden -RedirectStandardError $taskErrorPath -RedirectStandardOutput $taskOutputPath -PassThru
        [void]$taskActive.Add([pscustomobject]@{
            Index = $taskIndex; Process = $taskProcess; Path = $taskPartPath;
            ExpectedLength = $taskEnd - $taskStart + 1; ErrorPath = $taskErrorPath
        })
    }

    foreach ($taskJob in @($taskActive)) {
        if ($taskJob.Process.HasExited) {
            $taskJob.Process.WaitForExit()
            if ($taskJob.Process.ExitCode -ne 0) {
                Get-Content -LiteralPath $taskJob.ErrorPath
                throw "Artifact chunk $($taskJob.Index) failed with exit code $($taskJob.Process.ExitCode)"
            }
            if ((Get-Item -LiteralPath $taskJob.Path).Length -ne $taskJob.ExpectedLength) {
                throw "Artifact chunk $($taskJob.Index) has an unexpected length"
            }
            [void]$taskActive.Remove($taskJob)
            $taskCompleted++
            Write-Output ('{0}: {1}/{2} chunks downloaded' -f [System.IO.Path]::GetFileName($taskDestination), $taskCompleted, $taskChunkCount)
        }
    }
    if ($taskActive.Count -gt 0) { Start-Sleep -Milliseconds 500 }
}

$taskAssemblyPath = $taskDestination + '.assembling'
$taskOutputStream = [System.IO.File]::Create($taskAssemblyPath)
try {
    for ($taskIndex = 0; $taskIndex -lt $taskChunkCount; $taskIndex++) {
        $taskPartPath = Join-Path $taskPartsDir ('{0:D4}.part' -f $taskIndex)
        $taskInputStream = [System.IO.File]::OpenRead($taskPartPath)
        try { $taskInputStream.CopyTo($taskOutputStream) } finally { $taskInputStream.Dispose() }
    }
} finally {
    $taskOutputStream.Dispose()
}

$taskActualSha = (Get-FileHash -LiteralPath $taskAssemblyPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($taskActualSha -ne $Sha256.ToLowerInvariant()) { throw 'Artifact SHA256 verification failed' }
Move-Item -LiteralPath $taskAssemblyPath -Destination $taskDestination -Force
[pscustomobject]@{ File = $taskDestination; Bytes = $Length; SHA256 = $taskActualSha; Verified = $true } | ConvertTo-Json
