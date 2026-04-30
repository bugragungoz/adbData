## 2024-06-25 - Avoid PowerShell Pipelines in Hot Paths
**Learning:** PowerShell pipelines (`| ForEach-Object`) create significant overhead due to object wrapping and parameter binding per iteration. In high-frequency functions like `Write-Log`, this overhead compounds rapidly.
**Action:** Use native `foreach` loops and `[System.Text.StringBuilder]` for string concatenation in performance-critical code paths to minimize allocation and pipeline overhead. Always cast `.Append()` calls to `[void]` to suppress return values.
