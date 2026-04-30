$Context = @{
    Action = "ExecuteADBCommand"
    Resource = "Device123"
    Result = "Attempt"
    Details = "Command: adb -s Device123 shell ls"
    Metadata = "Test"
}

$sw = [Diagnostics.Stopwatch]::StartNew()
for ($i=0; $i -lt 10000; $i++) {
    $contextStr = ($Context.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
}
$sw.Stop()
Write-Host "Pipeline: $($sw.ElapsedMilliseconds)ms"

$sw.Restart()
for ($i=0; $i -lt 10000; $i++) {
    $sb = [System.Text.StringBuilder]::new()
    $first = $true
    foreach ($entry in $Context.GetEnumerator()) {
        if (-not $first) {
            [void]$sb.Append(", ")
        }
        [void]$sb.Append($entry.Key)
        [void]$sb.Append("=")
        [void]$sb.Append($entry.Value)
        $first = $false
    }
    $contextStr = $sb.ToString()
}
$sw.Stop()
Write-Host "StringBuilder: $($sw.ElapsedMilliseconds)ms"
