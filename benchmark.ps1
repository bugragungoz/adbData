
function Clear-SensitiveData-Old {
    param(
        [ref]$Variable,
        [int]$OverwritePasses = 3
    )

    if ($null -eq $Variable.Value) {
        return
    }

    $originalType = $Variable.Value.GetType()

    for ($pass = 1; $pass -le $OverwritePasses; $pass++) {
        switch ($pass) {
            1 {
                if ($originalType -eq [string]) {
                    $Variable.Value = "0" * $Variable.Value.Length
                }
            }
            2 {
                if ($originalType -eq [string]) {
                    $Variable.Value = [string]::new([char]0xFF, $Variable.Value.Length)
                }
            }
            3 {
                if ($originalType -eq [string]) {
                    $randomChars = -join ((0..($Variable.Value.Length-1)) | ForEach-Object {
                        [char](Get-Random -Minimum 32 -Maximum 127)
                    })
                    $Variable.Value = $randomChars
                }
            }
        }
    }

    $Variable.Value = $null

    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()
}

function Clear-SensitiveData-New {
    param(
        [ref]$Variable,
        [int]$OverwritePasses = 3
    )

    if ($null -eq $Variable.Value) {
        return
    }

    $originalType = $Variable.Value.GetType()

    for ($pass = 1; $pass -le $OverwritePasses; $pass++) {
        switch ($pass) {
            1 {
                if ($originalType -eq [string]) {
                    $Variable.Value = "0" * $Variable.Value.Length
                }
            }
            2 {
                if ($originalType -eq [string]) {
                    $Variable.Value = [string]::new([char]0xFF, $Variable.Value.Length)
                }
            }
            3 {
                if ($originalType -eq [string]) {
                    $randomChars = -join ((0..($Variable.Value.Length-1)) | ForEach-Object {
                        [char](Get-Random -Minimum 32 -Maximum 127)
                    })
                    $Variable.Value = $randomChars
                }
            }
        }
    }

    $Variable.Value = $null
    # GC removed
}

$iterations = 100
$testData = "some sensitive hash value"

$oldTime = Measure-Command {
    for ($i = 0; $i -lt $iterations; $i++) {
        $val = $testData
        Clear-SensitiveData-Old -Variable ([ref]$val)
    }
}

$newTime = Measure-Command {
    for ($i = 0; $i -lt $iterations; $i++) {
        $val = $testData
        Clear-SensitiveData-New -Variable ([ref]$val)
    }
}

Write-Host "Old Time ($iterations iterations): $($oldTime.TotalMilliseconds) ms"
Write-Host "New Time ($iterations iterations): $($newTime.TotalMilliseconds) ms"
Write-Host "Improvement: $(($oldTime.TotalMilliseconds - $newTime.TotalMilliseconds) / $oldTime.TotalMilliseconds * 100)% "
