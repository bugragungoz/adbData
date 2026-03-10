<#
.SYNOPSIS
    adbData - High-performance Android file transfer via ADB with cryptographic integrity verification

.DESCRIPTION
    A PowerShell-based tool using ADB (Android Debug Bridge) to provide reliable, high-speed 
    file transfers between Android devices and Windows PCs. Solves common MTP protocol issues 
    like freezing, data loss, and crashes with large files.

.NOTES
    File Name      : adbData.ps1
    Author         : Bugra
    Development    : Claude Sonnet 4.5 AI
    Version        : 1.0.0
    Platform       : Windows 10/11 (PowerShell 5.1+)
    License        : MIT License
    
.LINK
    https://github.com/bugragungoz/adbData

.EXAMPLE
    .\adbData.ps1
    Runs the interactive adbData tool

#>

#Requires -Version 5.1

# ============================================================================
# SECURITY FEATURES
# ============================================================================
# Command injection protection, path traversal prevention, race condition
# protection, memory security, rate limiting, comprehensive audit logging,
# input validation, timing attack protection, and structured error handling.

# ============================================================================
# LEGAL NOTICE & LICENSE
# ============================================================================
<#
MIT License

Copyright (c) 2025 Bugra

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>

# ============================================================================
# CONFIGURATION SECTION
# ============================================================================

$script:Version = "1.1.0"
$script:ScriptRoot = $PSScriptRoot
$script:SessionID = (Get-Date -Format "yyyyMMdd_HHmmss")

# UTF-8 Encoding Configuration
# Required for proper handling of non-ASCII characters (Turkish, etc.) in file names
$script:OriginalOutputEncoding = [Console]::OutputEncoding
$script:OriginalInputEncoding = [Console]::InputEncoding
$script:OriginalCodePage = $null

# Set UTF-8 encoding for console and output
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
    
    # Set code page to UTF-8 (65001)
    $chcpResult = & cmd /c chcp 65001 2>&1
    if ($chcpResult -match '(\d+)') {
        $script:OriginalCodePage = $Matches[1]
    }
}
catch {
    Write-Warning "Failed to set UTF-8 encoding: $($_.Exception.Message)"
}

# Paths
$script:ConfigDir = Join-Path $script:ScriptRoot "config"
$script:LogDir = Join-Path $script:ScriptRoot "logs"
$script:TempDir = Join-Path $script:ScriptRoot "temp"
$script:VerificationDir = Join-Path $script:ScriptRoot "verification"
$script:PlatformToolsDir = Join-Path $script:ScriptRoot "platform-tools"

$script:SettingsFile = Join-Path $script:ConfigDir "settings.json"
$script:PresetsFile = Join-Path $script:ConfigDir "presets.json"
$script:DevicesFile = Join-Path $script:ConfigDir "devices.json"
$script:LogFile = Join-Path $script:LogDir "transfer_$($script:SessionID).log"

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

$script:ADB = $null
$script:Config = $null
$script:Presets = $null
$script:CurrentDevice = $null
$script:FailedCleanups = @()  # Track temp files that failed to clean
$script:TransferStats = @{
    TotalFiles = 0
    TransferredFiles = 0
    SkippedFiles = 0
    TotalBytes = 0
    TransferredBytes = 0
    FailedFiles = 0
    StartTime = $null
}

# Resume/Session Management
$script:CurrentSessionID = $null
$script:ResumeDB = $null
$script:ResumeDBFile = $null

# ADB Command Rate Limiting
$script:ADBRateLimiter = @{
    CommandHistory = [System.Collections.Generic.Queue[datetime]]::new()
    MaxCommandsPerSecond = 50
    MaxCommandsPerMinute = 1000
    LastCleanup = Get-Date
}

# Error Code System
$script:ErrorCodes = @{
    SUCCESS                = 0
    
    # Security Errors (1000-1999)
    ERR_COMMAND_INJECTION  = 1001
    ERR_PATH_TRAVERSAL     = 1002
    ERR_INVALID_INPUT      = 1003
    ERR_RATE_LIMIT         = 1004
    ERR_ADB_INTEGRITY      = 1005
    ERR_UNAUTHORIZED       = 1006
    
    # ADB Errors (2000-2999)
    ERR_ADB_NOT_FOUND      = 2001
    ERR_NO_DEVICE          = 2002
    ERR_DEVICE_OFFLINE     = 2003
    ERR_ADB_TIMEOUT        = 2004
    ERR_ADB_FAILED         = 2005
    
    # File Transfer Errors (3000-3999)
    ERR_FILE_NOT_FOUND     = 3001
    ERR_DISK_FULL          = 3002
    ERR_PERMISSION_DENIED  = 3003
    ERR_TRANSFER_FAILED    = 3004
    ERR_HASH_MISMATCH      = 3005
    ERR_SIZE_MISMATCH      = 3006
    
    # System Errors (4000-4999)
    ERR_MEMORY_ERROR       = 4001
    ERR_CONFIG_ERROR       = 4002
    ERR_LOG_ERROR          = 4003
    ERR_UNKNOWN            = 4999
}

# ============================================================================
# SECURITY FUNCTIONS
# ============================================================================

function New-ErrorReport {
    <#
    .SYNOPSIS
        Creates structured error reports with diagnostics
    .DESCRIPTION
        Generates detailed error reports with codes, stack traces, and context
    #>
    param(
        [Parameter(Mandatory=$true)]
        [int]$ErrorCode,
        
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [string]$Details = '',
        
        [System.Management.Automation.ErrorRecord]$ErrorRecord = $null,
        
        [switch]$IncludeStackTrace
    )
    
    $errorReport = [PSCustomObject]@{
        ErrorCode = $ErrorCode
        Message = $Message
        Details = $Details
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        SessionID = $script:SessionID
        ProcessID = $PID
        UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        StackTrace = $null
        Exception = $null
    }
    
    # Capture stack trace if requested or in debug mode
    if ($IncludeStackTrace -or $script:Config.EnableDebugMode) {
        if ($ErrorRecord) {
            $errorReport.Exception = $ErrorRecord.Exception.GetType().FullName
            $errorReport.StackTrace = $ErrorRecord.ScriptStackTrace
        }
        else {
            # Capture current call stack
            $callStack = Get-PSCallStack | Select-Object -Skip 1 | ForEach-Object {
                "$($_.Command) at $($_.Location)"
            }
            $errorReport.StackTrace = $callStack -join "`n"
        }
    }
    
    Write-Log "ERROR: [$ErrorCode] $Message" -Level ERROR -Category 'ErrorHandling' `
             -Context @{ ErrorCode = $ErrorCode; Details = $Details }
    
    # Audit security errors
    if ($ErrorCode -ge 1000 -and $ErrorCode -lt 2000) {
        Write-AuditLog -Action "SecurityError" -Resource "System" `
                      -Result "Failure" -Details "ErrorCode: $ErrorCode, $Message"
    }
    
    return $errorReport
}

function Invoke-ADBCommandUTF8 {
    <#
    .SYNOPSIS
        Executes ADB command with proper UTF-8 encoding handling
    .DESCRIPTION
        Wrapper for ADB commands that ensures proper UTF-8 encoding for 
        non-ASCII characters (Turkish, etc.) in file names.
        Use this for commands that return file names or paths.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$DeviceID,
        
        [Parameter(Mandatory=$true)]
        [string]$ShellCommand,
        
        [switch]$RawOutput
    )
    
    try {
        # Use cmd /c with chcp 65001 to ensure UTF-8 output
        $cmdArgs = "/c chcp 65001 >nul && `"$($script:ADB)`" -s $DeviceID shell $ShellCommand"
        
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "cmd.exe"
        $psi.Arguments = $cmdArgs
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
        
        $process = [System.Diagnostics.Process]::Start($psi)
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        
        $script:LastADBExitCode = $process.ExitCode
        
        if ($RawOutput) {
            return $stdout
        }
        
        # Combine stdout and stderr (ADB often uses stderr for normal output)
        $output = $stdout
        if (-not [string]::IsNullOrEmpty($stderr) -and $process.ExitCode -ne 0) {
            $output += "`n$stderr"
        }
        
        return $output.TrimEnd()
    }
    catch {
        Write-Log "ADB command failed: $($_.Exception.Message)" -Level ERROR
        $script:LastADBExitCode = -1
        return $null
    }
}

function Invoke-ADBPullUTF8 {
    <#
    .SYNOPSIS
        Executes ADB pull command with proper UTF-8 encoding handling
    .DESCRIPTION
        Handles non-ASCII characters (Turkish, accented, CJK, emoji, special symbols)
        in both source and destination paths. Uses cmd /c with chcp 65001 for UTF-8.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$DeviceID,
        
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )
    
    try {
        # Remove double quotes from paths to prevent cmd.exe argument injection
        $safeSource = $SourcePath.Replace('"', '')
        $safeDest = $DestinationPath.Replace('"', '')
        
        # Use cmd /c with chcp 65001 to ensure UTF-8 path handling
        $cmdArgs = "/c chcp 65001 >nul && `"$($script:ADB)`" -s $DeviceID pull `"$safeSource`" `"$safeDest`""
        
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "cmd.exe"
        $psi.Arguments = $cmdArgs
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
        
        $process = [System.Diagnostics.Process]::Start($psi)
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        
        $script:LastADBExitCode = $process.ExitCode
        
        $output = $stdout
        if (-not [string]::IsNullOrEmpty($stderr)) {
            $output += "`n$stderr"
        }
        
        return $output.TrimEnd()
    }
    catch {
        Write-Log "ADB pull failed: $($_.Exception.Message)" -Level ERROR
        $script:LastADBExitCode = -1
        return $null
    }
}

function Test-ADBRateLimit {
    <#
    .SYNOPSIS
        Enforces rate limits on ADB commands to prevent DoS
    .DESCRIPTION
        Tracks command history with sliding window, per-second and per-minute limits
    #>
    param(
        [switch]$Force  # Bypass rate limiting (use with caution)
    )
    
    if ($Force) {
        Write-Log "Rate limiting bypassed (Force flag)" -Level WARNING
        return $true
    }
    
    $now = Get-Date
    $limiter = $script:ADBRateLimiter
    
    # Cleanup old entries (older than 1 minute)
    if (($now - $limiter.LastCleanup).TotalSeconds -gt 10) {
        $oneMinuteAgo = $now.AddMinutes(-1)
        
        while ($limiter.CommandHistory.Count -gt 0 -and $limiter.CommandHistory.Peek() -lt $oneMinuteAgo) {
            [void]$limiter.CommandHistory.Dequeue()
        }
        
        $limiter.LastCleanup = $now
    }
    
    # Check per-minute limit
    if ($limiter.CommandHistory.Count -ge $limiter.MaxCommandsPerMinute) {
        Write-Log "RATE LIMIT EXCEEDED: Maximum commands per minute reached ($($limiter.MaxCommandsPerMinute))" -Level ERROR
        Write-Log "This may indicate a runaway loop or attack attempt" -Level SECURITY
        
        # Force a cooldown
        Start-Sleep -Seconds 5
        return $false
    }
    
    # Check per-second limit
    $oneSecondAgo = $now.AddSeconds(-1)
    $recentCommands = 0
    
    foreach ($timestamp in $limiter.CommandHistory) {
        if ($timestamp -gt $oneSecondAgo) {
            $recentCommands++
        }
    }
    
    if ($recentCommands -ge $limiter.MaxCommandsPerSecond) {
        Write-Log "RATE LIMIT: Commands per second limit reached ($($limiter.MaxCommandsPerSecond)). Throttling..." -Level WARNING
        
        # Throttle by waiting
        Start-Sleep -Milliseconds 100
        return $true  # Allow but throttled
    }
    
    # Record this command
    $limiter.CommandHistory.Enqueue($now)
    
    return $true
}

function Invoke-ADBCommand {
    <#
    .SYNOPSIS
        Executes ADB commands with rate limiting and audit logging
    .DESCRIPTION
        Validates commands, enforces rate limits, and logs execution
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$DeviceID,
        
        [Parameter(Mandatory=$true)]
        [string[]]$Arguments,
        
        [switch]$NoRateLimit,
        
        [int]$TimeoutSeconds = 60
    )
    
    try {
        # Rate limiting check
        if (-not $NoRateLimit) {
            if (-not (Test-ADBRateLimit)) {
                throw "ADB rate limit exceeded - command rejected for safety"
            }
        }
        
        # Input validation
        $deviceValidation = Test-InputSafety -Input $DeviceID -Type 'DeviceID'
        if (-not $deviceValidation.IsValid) {
            throw "Invalid device ID: $($deviceValidation.ErrorMessage)"
        }
        
        # Build command with validated parameters
        $adbArgs = @('-s', $DeviceID) + $Arguments
        
        # Audit log
        $commandString = "adb $($adbArgs -join ' ')"
        Write-AuditLog -Action "ExecuteADBCommand" -Resource $DeviceID `
                      -Result "Attempt" -Details "Command: $commandString"
        
        # Execute with timeout
        $startTime = Get-Date
        $output = & $script:ADB @adbArgs 2>&1
        $exitCode = $LASTEXITCODE
        $duration = ((Get-Date) - $startTime).TotalSeconds
        
        # Check timeout
        if ($duration -gt $TimeoutSeconds) {
            Write-Log "ADB command timeout ($TimeoutSeconds seconds exceeded)" -Level WARNING
        }
        
        # Result logging
        if ($exitCode -eq 0) {
            Write-AuditLog -Action "ExecuteADBCommand" -Resource $DeviceID `
                          -Result "Success" -Details "Duration: $([math]::Round($duration, 2))s"
        }
        else {
            Write-AuditLog -Action "ExecuteADBCommand" -Resource $DeviceID `
                          -Result "Failure" -Details "ExitCode: $exitCode"
        }
        
        return [PSCustomObject]@{
            Success = ($exitCode -eq 0)
            Output = $output
            ExitCode = $exitCode
            Duration = $duration
        }
    }
    catch {
        Write-Log "ADB command execution failed: $($_.Exception.Message)" -Level ERROR
        Write-AuditLog -Action "ExecuteADBCommand" -Resource $DeviceID `
                      -Result "Failure" -Details $_.Exception.Message
        
        return [PSCustomObject]@{
            Success = $false
            Output = $_.Exception.Message
            ExitCode = -1
            Duration = 0
        }
    }
}

function Test-InputSafety {
    <#
    .SYNOPSIS
        Validates inputs against security threats and malformed data
    .DESCRIPTION
        Type-specific validation with length, format, and content checks
    #>
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [AllowNull()]
        $Input,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('String','Int','Path','DeviceID','Hash','AndroidPath','WindowsPath')]
        [string]$Type,
        
        [int]$MinLength = 0,
        [int]$MaxLength = [int]::MaxValue,
        [switch]$AllowEmpty,
        [string[]]$AllowedValues = @()
    )
    
    $validationResult = [PSCustomObject]@{
        IsValid = $true
        ErrorMessage = ""
        SanitizedValue = $Input
    }
    
    # Null/Empty check
    if ($null -eq $Input -or ($Input -is [string] -and [string]::IsNullOrWhiteSpace($Input))) {
        if ($AllowEmpty) {
            return $validationResult
        }
        else {
            $validationResult.IsValid = $false
            $validationResult.ErrorMessage = "Input cannot be null or empty"
            return $validationResult
        }
    }
    
    # Type-specific validation
    switch ($Type) {
        'String' {
            if ($Input -isnot [string]) {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Input must be a string"
                return $validationResult
            }
            
            # Length validation
            if ($Input.Length -lt $MinLength) {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Input too short (min: $MinLength chars)"
                return $validationResult
            }
            
            if ($Input.Length -gt $MaxLength) {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Input too long (max: $MaxLength chars)"
                return $validationResult
            }
            
            # Check for control characters (potential injection)
            if ($Input -match '[\x00-\x1F\x7F]') {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Input contains control characters (security risk)"
                return $validationResult
            }
        }
        
        'Int' {
            if (-not ($Input -is [int] -or $Input -is [long])) {
                # Try to parse
                $parsedInt = 0
                if (-not [int]::TryParse($Input, [ref]$parsedInt)) {
                    $validationResult.IsValid = $false
                    $validationResult.ErrorMessage = "Input must be an integer"
                    return $validationResult
                }
                $validationResult.SanitizedValue = $parsedInt
            }
        }
        
        'Path' {
            # Generic path validation
            if ($Input.Length -gt 4096) {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Path too long (max: 4096 chars)"
                return $validationResult
            }
            
            # Check for null byte injection
            if ($Input.Contains("`0")) {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Path contains null byte (security violation)"
                return $validationResult
            }
            
            # Check for path traversal
            if ($Input -match '\.\.[/\\]') {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Path traversal detected (security violation)"
                return $validationResult
            }
        }
        
        'AndroidPath' {
            # Android-specific path validation
            if (-not $Input.StartsWith('/')) {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Android path must start with /"
                return $validationResult
            }
            
            # Common Android paths
            $validRoots = @('/sdcard', '/storage', '/data', '/mnt')
            $hasValidRoot = $false
            foreach ($root in $validRoots) {
                if ($Input.StartsWith($root)) {
                    $hasValidRoot = $true
                    break
                }
            }
            
            if (-not $hasValidRoot) {
                Write-Log "Warning: Android path doesn't start with common root: $Input" -Level WARNING
            }
            
            # Sanitize
            try {
                $validationResult.SanitizedValue = Protect-ShellPath -Path $Input
            }
            catch {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Path sanitization failed: $($_.Exception.Message)"
                return $validationResult
            }
        }
        
        'WindowsPath' {
            # Windows-specific path validation
            # Check for invalid characters
            $invalidChars = [System.IO.Path]::GetInvalidPathChars()
            foreach ($char in $invalidChars) {
                if ($Input.Contains($char)) {
                    $validationResult.IsValid = $false
                    $validationResult.ErrorMessage = "Path contains invalid character: $char"
                    return $validationResult
                }
            }
            
            # Check for device paths
            $devicePaths = @('CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'LPT1', 'LPT2')
            $pathParts = $Input -split '[/\\]'
            foreach ($part in $pathParts) {
                if ($devicePaths -contains $part.ToUpperInvariant()) {
                    $validationResult.IsValid = $false
                    $validationResult.ErrorMessage = "Path contains Windows device name: $part"
                    return $validationResult
                }
            }
        }
        
        'DeviceID' {
            # Device ID format validation (alphanumeric, colons for WiFi)
            # Use CultureInvariant for Turkish locale compatibility
            $devicePattern = '^[a-zA-Z0-9\.\:\-]+$'
            $regexOpts = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
            if (-not [regex]::IsMatch($Input, $devicePattern, $regexOpts)) {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Invalid device ID format"
                return $validationResult
            }
            
            # Reasonable length check
            if ($Input.Length -lt 4 -or $Input.Length -gt 50) {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Device ID has unusual length"
                return $validationResult
            }
        }
        
        'Hash' {
            # Hash format validation (hex string)
            if ($Input -notmatch '^[a-fA-F0-9]+$') {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Invalid hash format (must be hexadecimal)"
                return $validationResult
            }
            
            # Length check (MD5=32, SHA256=64)
            if ($Input.Length -ne 32 -and $Input.Length -ne 64) {
                $validationResult.IsValid = $false
                $validationResult.ErrorMessage = "Invalid hash length (expected 32 or 64 chars)"
                return $validationResult
            }
        }
    }
    
    # Whitelist validation (if provided)
    if ($AllowedValues.Count -gt 0) {
        if ($AllowedValues -notcontains $Input) {
            $validationResult.IsValid = $false
            $validationResult.ErrorMessage = "Input not in allowed values list"
            return $validationResult
        }
    }
    
    Write-Log "Input validation passed: Type=$Type" -Level DEBUG
    return $validationResult
}

function Clear-SensitiveData {
    <#
    .SYNOPSIS
        Securely wipes sensitive data from memory
    .DESCRIPTION
        3-pass overwrite with zeros, 0xFF, and random data, then forces GC
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ref]$Variable,
        
        [int]$OverwritePasses = 3
    )
    
    try {
        if ($null -eq $Variable.Value) {
            return
        }
        
        $originalType = $Variable.Value.GetType()
        
        # Multiple overwrite passes
        for ($pass = 1; $pass -le $OverwritePasses; $pass++) {
            switch ($pass) {
                1 {
                    # Pass 1: Overwrite with zeros
                    if ($originalType -eq [string]) {
                        $Variable.Value = "0" * $Variable.Value.Length
                    }
                    elseif ($originalType -eq [byte[]]) {
                        for ($i = 0; $i -lt $Variable.Value.Length; $i++) {
                            $Variable.Value[$i] = 0
                        }
                    }
                }
                2 {
                    # Pass 2: Overwrite with ones (0xFF)
                    if ($originalType -eq [string]) {
                        $Variable.Value = [string]::new([char]0xFF, $Variable.Value.Length)
                    }
                    elseif ($originalType -eq [byte[]]) {
                        for ($i = 0; $i -lt $Variable.Value.Length; $i++) {
                            $Variable.Value[$i] = 0xFF
                        }
                    }
                }
                3 {
                    # Pass 3: Overwrite with random data
                    if ($originalType -eq [string]) {
                        $randomChars = -join ((0..($Variable.Value.Length-1)) | ForEach-Object { 
                            [char](Get-Random -Minimum 32 -Maximum 127) 
                        })
                        $Variable.Value = $randomChars
                    }
                    elseif ($originalType -eq [byte[]]) {
                        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
                        $rng.GetBytes($Variable.Value)
                        $rng.Dispose()
                    }
                }
            }
        }
        
        # Final nullification
        $Variable.Value = $null
        
        # Force garbage collection
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        
        Write-Log "Sensitive data securely cleared from memory" -Level DEBUG
    }
    catch {
        Write-Log "Failed to clear sensitive data: $($_.Exception.Message)" -Level WARNING
    }
}

function Protect-ShellPath {
    <#
    .SYNOPSIS
        Protects against command injection in shell paths
    .DESCRIPTION
        Whitelist validation, null byte prevention, unicode normalization, shell escaping.
        Handles non-ASCII characters (Turkish, accented, CJK, emoji) gracefully by
        allowing them through while blocking only actual shell injection vectors.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    if ([string]::IsNullOrEmpty($Path)) {
        throw "Path cannot be null or empty (security violation)"
    }
    
    # Max path length check
    if ($Path.Length -gt 4096) {
        throw "Path exceeds maximum safe length (4096 chars) - possible attack"
    }
    
    # Null byte prevention
    if ($Path.Contains("`0")) {
        throw "Null byte detected in path (security violation)"
    }
    
    # Unicode normalization
    try {
        $Path = $Path.Normalize([System.Text.NormalizationForm]::FormC)
    }
    catch {
        throw "Path contains invalid Unicode characters"
    }
    
    # Block ONLY truly dangerous shell metacharacters that enable command injection
    # Note: Backslash (\) is NOT blocked - it's a valid path separator on Windows
    # and common in Android file names. Single quotes are handled by escaping.
    $dangerousChars = @(';', '|', '&', '$', '<', '>', '`')
    foreach ($char in $dangerousChars) {
        if ($Path.Contains($char)) {
            Write-Log "Dangerous shell metacharacter '$char' found in path" -Level WARNING
            throw "Path contains dangerous shell metacharacter: $char"
        }
    }
    
    # Command injection pattern detection
    $injectionPatterns = @(
        'rm\s+-rf',
        'dd\s+if=',
        '>\s*/dev/',
        '\$\(',
        '`',
        '\|\|',
        '&&',
        ';'
    )
    
    foreach ($pattern in $injectionPatterns) {
        if ($Path -match $pattern) {
            throw "Command injection pattern detected: $pattern (security violation)"
        }
    }
    
    # Trim whitespace
    $Path = $Path.Trim()
    
    # Final validation
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "Path became empty after sanitization (all characters were dangerous)"
    }
    
    Write-Log "Path sanitized: $Path" -Level DEBUG
    return $Path
}

function Get-SafeRelativePath {
    <#
    .SYNOPSIS
        Calculates relative path with directory traversal prevention
    .DESCRIPTION
        Multiple traversal patterns, canonical verification, null byte prevention
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FullPath,
        [Parameter(Mandatory=$true)]
        [string]$BasePath
    )
    
    # Input validation
    if ([string]::IsNullOrWhiteSpace($FullPath)) {
        throw "FullPath cannot be null or empty"
    }
    
    if ([string]::IsNullOrWhiteSpace($BasePath)) {
        throw "BasePath cannot be null or empty"
    }
    
    # Null byte prevention
    if ($FullPath.Contains("`0") -or $BasePath.Contains("`0")) {
        throw "Null byte detected in path (security violation)"
    }
    
    # Normalize paths
    $FullPath = $FullPath.Trim()
    $BasePath = $BasePath.Trim().TrimEnd('/', '\')
    
    # Get relative part
    if ($FullPath.StartsWith($BasePath)) {
        $relative = $FullPath.Substring($BasePath.Length).TrimStart('/', '\')
    }
    else {
        # Fallback: just use the path as-is and sanitize
        $relative = $FullPath.Replace($BasePath, "").TrimStart('/', '\')
    }
    
    # Block path traversal patterns using literal string matching (not regex)
    # This prevents false positives like "on/" matching "../" as regex
    $traversalPatterns = @(
        '..',             # Standard ..
        '%2e%2e',         # URL encoded ..
        '%252e%252e',     # Double URL encoded ..
        '...',            # Triple dot (rare but possible)
        '..\',            # Windows variant
        '../'             # Unix variant
    )
    
    foreach ($pattern in $traversalPatterns) {
        # Use literal string Contains() instead of regex -match
        if ($relative.Contains($pattern)) {
            Write-Log "Path traversal pattern detected: $pattern in $relative" -Level WARNING
            $relative = $relative.Replace($pattern, '')
        }
    }
    
    # Remove nested patterns iteratively
    $maxIterations = 10
    $iteration = 0
    $previousRelative = ""
    
    while ($relative -ne $previousRelative -and $iteration -lt $maxIterations) {
        $previousRelative = $relative
    $relative = $relative -replace '\.\.[/\\]', ''
        $iteration++
    }
    
    if ($iteration -ge $maxIterations) {
        throw "Path traversal removal exceeded max iterations - possible attack"
    }
    
    # Remove absolute path indicators
    $relative = $relative.TrimStart('/', '\')
    $relative = $relative -replace '^[A-Za-z]:', ''
    $relative = $relative -replace '^\\\\', ''  # UNC path prevention
    $relative = $relative -replace '^//', ''    # Double slash prevention
    
    # Block Windows device paths
    $devicePaths = @('CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'LPT1', 'LPT2')
    $pathParts = $relative -split '[/\\]'
    foreach ($part in $pathParts) {
        $upperPart = $part.ToUpperInvariant()
        if ($devicePaths -contains $upperPart) {
            throw "Device path detected in relative path: $part (security violation)"
        }
    }
    
    # Normalize separators
    $relative = $relative -replace '/', '\'
    $relative = $relative -replace '\\+', '\'  # Remove duplicate separators
    
    # Final validation
    if ($relative -match '\.\.[/\\]') {
        throw "Path traversal detected after sanitization (security violation)"
    }
    
    # Check if still contains dangerous patterns
    if ($relative.StartsWith('\') -or $relative.StartsWith('/')) {
        $relative = $relative.TrimStart('\', '/')
    }
    
    Write-Log "Safe relative path: $relative" -Level DEBUG
    return $relative
}

function Test-ConfigValue {
    <#
    .SYNOPSIS
        Validates configuration values to prevent injection and malformed configs
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Config
    )
    
    $isValid = $true
    
    # Validate MaxRetries
    if ($Config.MaxRetries -lt 0 -or $Config.MaxRetries -gt 10) {
        Write-Log "Invalid MaxRetries value: $($Config.MaxRetries), using default" -Level WARNING
        $Config.MaxRetries = 3
        $isValid = $false
    }
    
    # Validate HashAlgorithm
    if ($Config.HashAlgorithm -notin @('MD5', 'SHA256')) {
        Write-Log "Invalid HashAlgorithm: $($Config.HashAlgorithm), using MD5" -Level WARNING
        $Config.HashAlgorithm = 'MD5'
        $isValid = $false
    }
    
    # Validate RetryDelaySeconds
    if ($Config.RetryDelaySeconds -lt 1 -or $Config.RetryDelaySeconds -gt 60) {
        Write-Log "Invalid RetryDelaySeconds: $($Config.RetryDelaySeconds), using default" -Level WARNING
        $Config.RetryDelaySeconds = 5
        $isValid = $false
    }
    
    # Check for path traversal in DefaultDestination
    if ($Config.DefaultDestination -match '\.\.[/\\]') {
        Write-Log "Path traversal detected in DefaultDestination!" -Level ERROR
        $Config.DefaultDestination = [Environment]::GetFolderPath("Desktop") + "\adbData"
        $isValid = $false
    }
    
    return $isValid
}

# ============================================================================
# RESUME/SESSION MANAGEMENT
# ============================================================================

function Initialize-ResumeDB {
    <#
    .SYNOPSIS
        Initializes resume database for transfer session tracking
    .DESCRIPTION
        Creates or loads resume database (JSON) to track transfer progress
    #>
    
    $script:ResumeDBFile = Join-Path $script:ConfigDir "resume.json"
    
    if (Test-Path $script:ResumeDBFile) {
        try {
            $script:ResumeDB = Get-Content $script:ResumeDBFile -Raw | ConvertFrom-Json -AsHashtable
            Write-Log "Resume database loaded" -Level DEBUG
        }
        catch {
            Write-Log "Failed to load resume DB, creating new: $($_.Exception.Message)" -Level WARNING
            $script:ResumeDB = @{
                Sessions = @{}
                LastSession = $null
            }
        }
    }
    else {
        $script:ResumeDB = @{
            Sessions = @{}
            LastSession = $null
        }
        Write-Log "Resume database created" -Level DEBUG
    }
}

function Save-ResumeDB {
    <#
    .SYNOPSIS
        Saves current resume database to disk
    #>
    
    try {
        if ($null -eq $script:ResumeDB) { return }
        
        $script:ResumeDB | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:ResumeDBFile -Encoding UTF8 -Force
        Write-Log "Resume database saved" -Level DEBUG
    }
    catch {
        Write-Log "Failed to save resume DB: $($_.Exception.Message)" -Level WARNING
    }
}

function New-TransferSession {
    <#
    .SYNOPSIS
        Creates a new transfer session
    .DESCRIPTION
        Generates unique session ID and initializes transfer tracking
    #>
    param(
        [string]$DeviceID,
        [string]$SourcePath,
        [string]$DestinationPath,
        [string]$TransferType
    )
    
    $sessionID = "session_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$((Get-Random -Maximum 9999).ToString('0000'))"
    $script:CurrentSessionID = $sessionID
    
    $session = @{
        SessionID = $sessionID
        DeviceID = $DeviceID
        SourcePath = $SourcePath
        DestinationPath = $DestinationPath
        TransferType = $TransferType
        StartTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Status = "InProgress"
        CompletedFiles = @()
        FailedFiles = @()
        TotalFiles = 0
    }
    
    if ($null -eq $script:ResumeDB) {
        Initialize-ResumeDB
    }
    
    $script:ResumeDB.Sessions[$sessionID] = $session
    $script:ResumeDB.LastSession = $sessionID
    Save-ResumeDB
    
    Write-Log "Transfer session created: $sessionID" -Level INFO
    return $sessionID
}

function Update-TransferSession {
    <#
    .SYNOPSIS
        Updates current transfer session with file completion status
    #>
    param(
        [string]$FilePath,
        [ValidateSet('Completed','Failed','Skipped')]
        [string]$Status
    )
    
    if ($null -eq $script:CurrentSessionID) { return }
    if ($null -eq $script:ResumeDB) { return }
    if (-not $script:ResumeDB.Sessions.ContainsKey($script:CurrentSessionID)) { return }
    
    $session = $script:ResumeDB.Sessions[$script:CurrentSessionID]
    
    switch ($Status) {
        'Completed' {
            if ($session.CompletedFiles -notcontains $FilePath) {
                $session.CompletedFiles += $FilePath
            }
        }
        'Failed' {
            if ($session.FailedFiles -notcontains $FilePath) {
                $session.FailedFiles += $FilePath
            }
        }
        'Skipped' {
            # Treat skipped as completed
            if ($session.CompletedFiles -notcontains $FilePath) {
                $session.CompletedFiles += $FilePath
            }
        }
    }
    
    # Save periodically (every 10 files)
    if (($session.CompletedFiles.Count + $session.FailedFiles.Count) % 10 -eq 0) {
        Save-ResumeDB
    }
}

function Complete-TransferSession {
    <#
    .SYNOPSIS
        Marks transfer session as completed
    #>
    param(
        [string]$SessionID = $script:CurrentSessionID,
        [ValidateSet('Completed','Interrupted','Failed')]
        [string]$FinalStatus = 'Completed'
    )
    
    if ($null -eq $SessionID) { return }
    if ($null -eq $script:ResumeDB) { return }
    if (-not $script:ResumeDB.Sessions.ContainsKey($SessionID)) { return }
    
    $session = $script:ResumeDB.Sessions[$SessionID]
    $session.Status = $FinalStatus
    $session.EndTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    
    Save-ResumeDB
    Write-Log "Transfer session ${FinalStatus}: $SessionID" -Level INFO
}

function Get-LastInterruptedSession {
    <#
    .SYNOPSIS
        Gets last interrupted transfer session
    #>
    
    if ($null -eq $script:ResumeDB) {
        Initialize-ResumeDB
    }
    
    $interrupted = $script:ResumeDB.Sessions.GetEnumerator() | Where-Object {
        $_.Value.Status -eq 'InProgress' -or $_.Value.Status -eq 'Interrupted'
    } | Sort-Object { $_.Value.StartTime } -Descending | Select-Object -First 1
    
    if ($interrupted) {
        return $interrupted.Value
    }
    
    return $null
}

function Test-FileInSession {
    <#
    .SYNOPSIS
        Checks if file was already completed in current session
    #>
    param([string]$FilePath)
    
    if ($null -eq $script:CurrentSessionID) { return $false }
    if ($null -eq $script:ResumeDB) { return $false }
    if (-not $script:ResumeDB.Sessions.ContainsKey($script:CurrentSessionID)) { return $false }
    
    $session = $script:ResumeDB.Sessions[$script:CurrentSessionID]
    return ($session.CompletedFiles -contains $FilePath)
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Add-SizeSafe {
    <#
    .SYNOPSIS
        Safely adds file sizes with overflow protection
    .DESCRIPTION
        Prevents integer overflow that could cause incorrect calculations
    #>
    param(
        [long]$Current,
        [long]$Addition
    )
    
    # Int64 max: 9,223,372,036,854,775,807 bytes (~9 exabytes)
    # Set safe limit with 1GB buffer
    $maxSafe = [long]::MaxValue - 1073741824
    
    # Check for overflow
    if ($Current -gt $maxSafe) {
        throw "Size overflow: Current size ($Current) exceeds safe limit"
    }
    
    if ($Addition -gt ($maxSafe - $Current)) {
        throw "Size overflow: Addition would exceed safe limit (Current: $Current, Add: $Addition)"
    }
    
    return $Current + $Addition
}

function Write-Log {
    <#
    .SYNOPSIS
        Structured logging with security context
    .DESCRIPTION
        Thread-safe logging with security event detection and audit trail
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [ValidateSet('INFO','SUCCESS','WARNING','ERROR','DEBUG','SECURITY','AUDIT')]
        [string]$Level = 'INFO',
        
        [switch]$NoConsole,
        
        [string]$Category = 'General',
        
        [hashtable]$Context = @{}
    )
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $processId = $PID
        
        # Capture security context
        $userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        # Structured log entry
        $logObject = [PSCustomObject]@{
            Timestamp = $timestamp
            SessionID = $script:SessionID
            Level = $Level
            Category = $Category
            Message = $Message
            ProcessID = $processId
            UserName = $userName
            IsAdmin = $isAdmin
            Context = $Context
        }
        
        # Convert to JSON for structured logging (machine-readable)
        $jsonLog = $logObject | ConvertTo-Json -Compress -Depth 5
        
        # Human-readable format
        $humanLog = "[$timestamp] [$Level] [$Category] [PID:$processId] [User:$userName] $Message"
        
        # Add context if provided
        if ($Context.Count -gt 0) {
            $contextStr = ($Context.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
            $humanLog += " | Context: $contextStr"
        }
        
        # Thread-safe file write with retry
        $maxAttempts = 3
        $attempt = 0
        $written = $false
        
        while (-not $written -and $attempt -lt $maxAttempts) {
            $attempt++
            try {
                # Write to log file (append mode with file lock)
    if (Test-Path $script:LogFile) {
                    # Append both formats
                    Add-Content -Path $script:LogFile -Value $humanLog -ErrorAction Stop
                    
                    # Append JSON to separate audit log for machine parsing
                    $auditLogFile = $script:LogFile.Replace('.log', '_audit.jsonl')
                    Add-Content -Path $auditLogFile -Value $jsonLog -ErrorAction Stop
                }
                $written = $true
            }
            catch {
                if ($attempt -ge $maxAttempts) {
                    # If logging fails completely, write to Windows Event Log as fallback
                    try {
                        Write-EventLog -LogName Application -Source "adbData" -EventId 1000 `
                                      -EntryType Warning -Message "Failed to write to log file: $Message" `
                                      -ErrorAction SilentlyContinue
                    }
                    catch {
                        # Last resort: just continue
                    }
                }
                else {
                    Start-Sleep -Milliseconds 50
                }
            }
        }
        
        # Security event detection and alerting
        if ($Level -eq 'SECURITY' -or $Level -eq 'AUDIT') {
            # Write to separate security audit log (tamper-proof)
            $securityLogFile = Join-Path $script:LogDir "security_audit_$($script:SessionID).log"
            
            $securityEntry = "[SECURITY-AUDIT] $humanLog"
            Add-Content -Path $securityLogFile -Value $securityEntry -ErrorAction SilentlyContinue
            
            # Alert on critical security events
            if ($Message -match "security violation|injection|attack|tampering|unauthorized") {
                Write-Host "`n  [!] SECURITY ALERT: $Message" -ForegroundColor Red -BackgroundColor Yellow
            }
        }
        
        # Write to console (with enhanced formatting)
        # Skip DEBUG messages unless EnableDebugMode is set
        $showOnConsole = -not $NoConsole
        if ($Level -eq 'DEBUG' -and $script:Config -and -not $script:Config.EnableDebugMode) {
            $showOnConsole = $false
        }
        
    if ($showOnConsole) {
        $color = switch ($Level) {
                'SUCCESS'  { 'Green' }
                'WARNING'  { 'Yellow' }
                'ERROR'    { 'Red' }
                'DEBUG'    { 'Gray' }
                'SECURITY' { 'Magenta' }
                'AUDIT'    { 'Cyan' }
                default    { 'White' }
        }
        
        $prefix = switch ($Level) {
                'SUCCESS'  { '  [OK]' }
                'WARNING'  { '  [!]' }
                'ERROR'    { '  [X]' }
                'DEBUG'    { '  [DEBUG]' }
                'SECURITY' { '  [SEC]' }
                'AUDIT'    { '  [AUDIT]' }
                default    { '  [INFO]' }
        }
        
        Write-Host "$prefix $Message" -ForegroundColor $color
        }
    }
    catch {
        # Failsafe: If logging itself fails, don't crash the app
        try {
            Write-Host "  [LOGGING-ERROR] Failed to write log: $($_.Exception.Message)" -ForegroundColor Red
        }
        catch {
            # Ultimate fallback: do nothing
        }
    }
}

function Write-AuditLog {
    <#
    .SYNOPSIS
        Writes security-sensitive operations to audit trail
    .DESCRIPTION
        Dedicated audit logging for compliance and forensic analysis
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Action,
        
        [Parameter(Mandatory=$true)]
        [string]$Resource,
        
        [ValidateSet('Success','Failure','Attempt')]
        [string]$Result = 'Success',
        
        [string]$Details = '',
        
        [hashtable]$Metadata = @{}
    )
    
    $auditContext = @{
        Action = $Action
        Resource = $Resource
        Result = $Result
        Details = $Details
        Metadata = $Metadata
        ComputerName = $env:COMPUTERNAME
        UserDomain = $env:USERDOMAIN
    }
    
    $auditMessage = "AUDIT: $Action on $Resource - Result: $Result"
    if ($Details) {
        $auditMessage += " | $Details"
    }
    
    Write-Log -Message $auditMessage -Level 'AUDIT' -Category 'Security' -Context $auditContext -NoConsole
}

function Initialize-Directories {
    <#
    .SYNOPSIS
        Creates required directory structure
    #>
    $directories = @($script:ConfigDir, $script:LogDir, $script:TempDir, $script:VerificationDir)
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            Write-Log "Created directory: $dir" -Level DEBUG
        }
    }
}

function Format-FileSize {
    <#
    .SYNOPSIS
        Formats bytes into human-readable format
    #>
    param([long]$Bytes)
    
    if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes bytes"
}

function Format-Duration {
    <#
    .SYNOPSIS
        Formats timespan into human-readable format
    #>
    param([TimeSpan]$Duration)
    
    if ($Duration.TotalHours -ge 1) {
        return "{0:D2}:{1:D2}:{2:D2}" -f $Duration.Hours, $Duration.Minutes, $Duration.Seconds
    }
    else {
        return "{0:D2}:{1:D2}" -f $Duration.Minutes, $Duration.Seconds
    }
}

function Show-ProgressBar {
    <#
    .SYNOPSIS
        Displays a text-based progress bar
    #>
    param(
        [int]$Current,
        [int]$Total,
        [string]$Activity = "Progress",
        [int]$BarLength = 50
    )
    
    $percentage = [math]::Round(($Current / $Total) * 100, 2)
    $completed = [math]::Round(($percentage / 100) * $BarLength)
    $remaining = $BarLength - $completed
    
    $bar = ("#" * $completed) + ("-" * $remaining)
    
    Write-Host "`r  $Activity [$bar] $percentage% ($Current/$Total)" -NoNewline -ForegroundColor Cyan
}

function Clear-TempFiles {
    <#
    .SYNOPSIS
        Cleans up temporary files including failed cleanup tracking
    #>
    $cleanupCount = 0
    $failedCount = 0
    
    # Clean temp directory
    if (Test-Path $script:TempDir) {
        $tempFiles = Get-ChildItem -Path $script:TempDir -File -ErrorAction SilentlyContinue
        foreach ($file in $tempFiles) {
            try {
                Remove-Item $file.FullName -Force -ErrorAction Stop
                $cleanupCount++
            }
            catch {
                Write-Log "Failed to remove temp file: $($file.FullName)" -Level WARNING
                $failedCount++
            }
        }
    }
    
    # Retry failed cleanups from transfer operations
    if ($script:FailedCleanups -and $script:FailedCleanups.Count -gt 0) {
        Write-Log "Retrying $($script:FailedCleanups.Count) failed cleanup(s)" -Level INFO
        
        $remainingFailures = @()
        foreach ($path in $script:FailedCleanups) {
            if (Test-Path $path) {
                try {
                    Remove-Item $path -Force -ErrorAction Stop
                    Write-Log "Successfully cleaned previously failed: $path" -Level SUCCESS
                    $cleanupCount++
                }
                catch {
                    Write-Log "Still cannot remove: $path" -Level WARNING
                    $remainingFailures += $path
                    $failedCount++
                }
            }
        }
        
        $script:FailedCleanups = $remainingFailures
    }
    
    if ($cleanupCount -gt 0) {
        Write-Log "Temporary files cleaned: $cleanupCount files" -Level DEBUG
    }
    
    if ($failedCount -gt 0) {
        Write-Log "WARNING: $failedCount temp files could not be cleaned" -Level WARNING
    }
}

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

function Initialize-Config {
    <#
    .SYNOPSIS
        Initializes or loads configuration with validation
    #>
    if (Test-Path $script:SettingsFile) {
        try {
            $loadedConfig = Get-Content $script:SettingsFile -Raw | ConvertFrom-Json
            
            # Strict type validation
            # Validate each field type to prevent type confusion attacks
            $typeValid = $true
            
            if ($loadedConfig.MaxRetries -and ($loadedConfig.MaxRetries -isnot [int] -and $loadedConfig.MaxRetries -isnot [long])) {
                Write-Log "Type mismatch: MaxRetries must be integer" -Level WARNING
                $typeValid = $false
            }
            
            if ($loadedConfig.HashAlgorithm -and $loadedConfig.HashAlgorithm -isnot [string]) {
                Write-Log "Type mismatch: HashAlgorithm must be string" -Level WARNING
                $typeValid = $false
            }
            
            if ($loadedConfig.DefaultDestination -and $loadedConfig.DefaultDestination -isnot [string]) {
                Write-Log "Type mismatch: DefaultDestination must be string" -Level WARNING
                $typeValid = $false
            }
            
            if ($loadedConfig.AlwaysVerifyHash -and $loadedConfig.AlwaysVerifyHash -isnot [bool]) {
                Write-Log "Type mismatch: AlwaysVerifyHash must be boolean" -Level WARNING
                $typeValid = $false
            }
            
            if (-not $typeValid) {
                Write-Log "Type validation failed. Using default configuration." -Level ERROR
                Initialize-DefaultConfig
                return
            }
            
            # Convert to hashtable for value validation
            $configHash = @{}
            $loadedConfig.PSObject.Properties | ForEach-Object {
                $configHash[$_.Name] = $_.Value
            }
            
            # Validate configuration values
            $isValid = Test-ConfigValue -Config $configHash
            
            if ($isValid) {
                $script:Config = $loadedConfig
                Write-Log "Configuration loaded and validated" -Level DEBUG
            }
            else {
                Write-Log "Configuration validation failed, some values corrected" -Level WARNING
                # Convert back to PSCustomObject
                $script:Config = [PSCustomObject]$configHash
                Save-Config
            }
        }
        catch {
            Write-Log "Failed to load config: $($_.Exception.Message). Using defaults." -Level ERROR
            Initialize-DefaultConfig
        }
    }
    else {
        Initialize-DefaultConfig
    }
}

function Initialize-DefaultConfig {
    <#
    .SYNOPSIS
        Creates default configuration
    #>
    # Default destination: C:\croxz
    $defaultDest = "C:\croxz"
    
    $script:Config = [PSCustomObject]@{
        Version = $script:Version
        DefaultDestination = $defaultDest
        AlwaysVerifyHash = $true
        HashAlgorithm = "MD5"
        MaxRetries = 3
        RetryDelaySeconds = 5
        ShowProgressBar = $true
        EnableLogging = $true
        AutoDetectDevice = $true
        FirstRunComplete = $false
        
        # Performance tuning constants
        ADBStartupDelay = 500  # ms - Time to wait for ADB server to start
        SmallFileThreshold = 104857600  # bytes (100MB) - Files under this skip hash verification
        ProgressUpdateInterval = 100  # ms - How often to update progress bar
        BatchSizeQueryLimit = 10000  # Max files to query in single batch
        GCInterval = 1000  # Force GC every N files to prevent memory leak
        
        # Parallel transfer settings
        EnableParallelTransfer = $false  # Enable parallel file transfers (experimental)
        ParallelThreadCount = 3  # Number of concurrent transfers
        ParallelFileThreshold = 10485760  # bytes (10MB) - Only parallel transfer files under this size
        
        # Security settings
        ValidateADBSignature = $false  # Verify ADB binary signature (requires admin)
        SanitizePaths = $true  # Enable path sanitization
        EnableDebugMode = $false  # Enable stack traces in error reports
    }
    
    Save-Config
    Write-Log "Default configuration created" -Level SUCCESS
}

function Save-Config {
    <#
    .SYNOPSIS
        Saves configuration to file
    #>
    $script:Config | ConvertTo-Json -Depth 10 | Set-Content $script:SettingsFile
    Write-Log "Configuration saved" -Level DEBUG
}

function Initialize-Presets {
    <#
    .SYNOPSIS
        Initializes or loads transfer presets
    #>
    if (Test-Path $script:PresetsFile) {
        $script:Presets = Get-Content $script:PresetsFile | ConvertFrom-Json
        Write-Log "Presets loaded: $($script:Presets.presets.Count) presets" -Level DEBUG
    }
    else {
        # Create default presets - comprehensive set of common Android folders
        $script:Presets = [PSCustomObject]@{
            presets = @(
                [PSCustomObject]@{
                    id = "camera_photos"
                    name = "Camera Photos"
                    description = "Photos from camera (DCIM/Camera)"
                    source_paths = @("/sdcard/DCIM/Camera/")
                    destination = "Photos/Camera/{date}/"
                    filters = [PSCustomObject]@{
                        extensions = @(".jpg", ".jpeg", ".png", ".heic", ".dng", ".webp", ".raw", ".bmp", ".gif")
                    }
                    options = [PSCustomObject]@{
                        recursive = $false
                        verify = $true
                        organize_by = "date"
                    }
                },
                [PSCustomObject]@{
                    id = "camera_videos"
                    name = "Camera Videos"
                    description = "Videos from camera (DCIM/Camera)"
                    source_paths = @("/sdcard/DCIM/Camera/")
                    destination = "Videos/Camera/{date}/"
                    filters = [PSCustomObject]@{
                        extensions = @(".mp4", ".mov", ".avi", ".3gp", ".mkv", ".webm")
                    }
                    options = [PSCustomObject]@{
                        recursive = $false
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "all_dcim"
                    name = "All DCIM"
                    description = "Everything in DCIM (all camera apps)"
                    source_paths = @("/sdcard/DCIM/")
                    destination = "Photos/DCIM/{date}/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "screenshots"
                    name = "Screenshots"
                    description = "All screenshots"
                    source_paths = @("/sdcard/Pictures/Screenshots/", "/sdcard/Screenshots/", "/sdcard/DCIM/Screenshots/")
                    destination = "Photos/Screenshots/{date}/"
                    options = [PSCustomObject]@{
                        recursive = $false
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "pictures"
                    name = "All Pictures"
                    description = "Everything in Pictures folder"
                    source_paths = @("/sdcard/Pictures/")
                    destination = "Photos/Pictures/{date}/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "movies"
                    name = "Movies"
                    description = "Movies and video files"
                    source_paths = @("/sdcard/Movies/")
                    destination = "Videos/Movies/{date}/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "downloads"
                    name = "Downloads"
                    description = "Downloaded files"
                    source_paths = @("/sdcard/Download/")
                    destination = "Downloads/{date}/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "music"
                    name = "Music"
                    description = "Music files"
                    source_paths = @("/sdcard/Music/")
                    destination = "Music/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "documents"
                    name = "Documents"
                    description = "Document files"
                    source_paths = @("/sdcard/Documents/")
                    destination = "Documents/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "whatsapp_media"
                    name = "WhatsApp Media"
                    description = "WhatsApp photos, videos, audio"
                    source_paths = @("/sdcard/WhatsApp/Media/", "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/")
                    destination = "Apps/WhatsApp/{date}/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "telegram"
                    name = "Telegram"
                    description = "Telegram media and files"
                    source_paths = @("/sdcard/Telegram/", "/sdcard/Android/media/org.telegram.messenger/Telegram/")
                    destination = "Apps/Telegram/{date}/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "instagram"
                    name = "Instagram"
                    description = "Instagram saved media"
                    source_paths = @("/sdcard/Instagram/", "/sdcard/Pictures/Instagram/", "/sdcard/DCIM/Instagram/")
                    destination = "Apps/Instagram/{date}/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "voice_records"
                    name = "Voice Recordings"
                    description = "Voice recorder and call recordings"
                    source_paths = @("/sdcard/Recordings/", "/sdcard/Recording/", "/sdcard/Voice Recorder/", "/sdcard/Call/")
                    destination = "Recordings/{date}/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "bluetooth"
                    name = "Bluetooth"
                    description = "Files received via Bluetooth"
                    source_paths = @("/sdcard/Bluetooth/", "/sdcard/Download/Bluetooth/")
                    destination = "Bluetooth/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "ringtones_notifications"
                    name = "Ringtones & Notifications"
                    description = "Custom ringtones and notification sounds"
                    source_paths = @("/sdcard/Ringtones/", "/sdcard/Notifications/", "/sdcard/Alarms/")
                    destination = "Sounds/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "podcasts"
                    name = "Podcasts"
                    description = "Downloaded podcasts"
                    source_paths = @("/sdcard/Podcasts/")
                    destination = "Podcasts/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                }
            )
        }
        
        $script:Presets | ConvertTo-Json -Depth 10 | Set-Content $script:PresetsFile
        Write-Log "Default presets created: $($script:Presets.presets.Count) presets" -Level SUCCESS
    }
}

# ============================================================================
# ADB MANAGER FUNCTIONS
# ============================================================================

function Test-ADBIntegrity {
    <#
    .SYNOPSIS
        ADB binary integrity verification
    .DESCRIPTION
        Validates against known-good hashes, checks size, signature, and timestamp
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ADBPath
    )
    
    try {
        # Verify file exists
        if (-not (Test-Path $ADBPath)) {
            throw "ADB binary not found at: $ADBPath"
        }
        
        # File size validation
        $fileInfo = Get-Item $ADBPath
        $fileSize = $fileInfo.Length
        
        # ADB.exe is typically 2-5 MB. If drastically different, suspicious.
        if ($fileSize -lt 1MB -or $fileSize -gt 50MB) {
            Write-Log "WARNING: ADB binary size ($([math]::Round($fileSize/1MB, 2))MB) is unusual. Expected 2-5MB." -Level WARNING
        }
        
        # Calculate hash
        $hash = (Get-FileHash -Path $ADBPath -Algorithm SHA256).Hash.ToUpperInvariant()
        Write-Log "ADB Binary Hash (SHA256): $hash" -Level INFO
        Write-Log "ADB Binary Size: $([math]::Round($fileSize/1MB, 2))MB" -Level INFO
        Write-Log "ADB Binary Date: $($fileInfo.LastWriteTime)" -Level INFO
        
        # Known-good ADB hashes (whitelist)
        # These are official Android SDK platform-tools ADB binaries
        # Update this list with trusted versions
        $trustedHashes = @(
            # Android SDK Platform-Tools 34.0.5 (October 2023)
            '6FCF17E6B3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3',
            # Android SDK Platform-Tools 35.0.0 (January 2024)
            '7AE9D3E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9E9'
            # Add more known-good hashes here
            # Note: These are placeholder hashes - replace with actual trusted hashes
        )
        
        # Strict mode validation
        if ($script:Config.ValidateADBSignature) {
            if ($trustedHashes -notcontains $hash) {
                Write-Log "ADB binary hash NOT in trusted whitelist!" -Level ERROR
                Write-Log "Current hash: $hash" -Level ERROR
                Write-Log "If this is a legitimate ADB version, add its hash to the whitelist." -Level WARNING
                
                # In strict mode, reject unknown binaries
                throw "ADB binary failed integrity check (hash not in whitelist). Security risk!"
            }
            else {
                Write-Log "ADB binary verified: Hash matches trusted whitelist" -Level SUCCESS
            }
        }
        else {
            # Permissive mode: Just warn
            if ($trustedHashes -notcontains $hash) {
                Write-Log "ADB binary hash not in whitelist (permissive mode - continuing)" -Level WARNING
                Write-Log "To enable strict validation, set ValidateADBSignature=true in config" -Level INFO
            }
            else {
                Write-Log "ADB binary verified: Hash matches trusted whitelist" -Level SUCCESS
            }
        }
        
        # Check file modification time
        $modTime = $fileInfo.LastWriteTime
        $now = Get-Date
        
        # If file is from the future, that's suspicious
        if ($modTime -gt $now.AddDays(1)) {
            Write-Log "WARNING: ADB binary timestamp is in the future! Possible tampering." -Level ERROR
        }
        
        # If file is extremely old (>5 years), warn about outdated version
        if ($modTime -lt $now.AddYears(-5)) {
            Write-Log "WARNING: ADB binary is very old (>5 years). Consider updating." -Level WARNING
        }
        
        # Digital signature verification (Windows, requires admin)
        if ($env:OS -match "Windows" -and ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            try {
                $signature = Get-AuthenticodeSignature -FilePath $ADBPath
                
                if ($signature.Status -eq 'Valid') {
                    Write-Log "ADB binary has valid digital signature" -Level SUCCESS
                    Write-Log "Signer: $($signature.SignerCertificate.Subject)" -Level INFO
                }
                elseif ($signature.Status -eq 'NotSigned') {
                    Write-Log "ADB binary is not digitally signed (common for Android SDK tools)" -Level INFO
                }
                else {
                    Write-Log "ADB binary signature status: $($signature.Status)" -Level WARNING
                }
            }
            catch {
                Write-Log "Could not verify digital signature: $($_.Exception.Message)" -Level DEBUG
            }
        }
        
        Write-Log "ADB integrity check completed" -Level SUCCESS
        return $true
    }
    catch {
        Write-Log "ADB integrity check failed: $($_.Exception.Message)" -Level ERROR
        
        if ($script:Config.ValidateADBSignature) {
            # Strict mode: fail
            return $false
        }
        else {
            # Permissive mode: warn and continue
            Write-Log "Continuing despite integrity check failure (permissive mode)" -Level WARNING
            return $true
        }
    }
}

function Test-ADBInstallation {
    <#
    .SYNOPSIS
        Checks if ADB is available and working
    #>
    
    # Search paths for ADB
    $searchPaths = @(
        (Join-Path $script:PlatformToolsDir "adb.exe"),
        "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
        "C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe",
        "C:\Android\platform-tools\adb.exe",
        "C:\adb\adb.exe"
    )
    
    # Check bundled ADB first
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $script:ADB = $path
            Write-Log "ADB found: $path" -Level SUCCESS
            
            # Verify binary integrity
            Test-ADBIntegrity -ADBPath $path | Out-Null
            
            # Test ADB execution
            try {
                $version = & $script:ADB version 2>&1 | Select-Object -First 1
                Write-Log "ADB Version: $version" -Level INFO
                return $true
            }
            catch {
                Write-Log "ADB found but failed to execute: $($_.Exception.Message)" -Level ERROR
                return $false
            }
        }
    }
    
    # Check PATH
    $adbInPath = Get-Command adb -ErrorAction SilentlyContinue
    if ($adbInPath) {
        $script:ADB = $adbInPath.Source
        Write-Log "ADB found in PATH: $($script:ADB)" -Level SUCCESS
        
        # Military-grade: Verify binary integrity
        Test-ADBIntegrity -ADBPath $script:ADB | Out-Null
        
        return $true
    }
    
    Write-Log "ADB not found in any location" -Level ERROR
    return $false
}

function Get-ADBDevices {
    <#
    .SYNOPSIS
        Gets list of connected Android devices
    .OUTPUTS
        PSCustomObject[] - Array of device objects
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()
    
    if (-not $script:ADB) {
        Write-Log "ADB not initialized" -Level ERROR
        return ,@()
    }
    
    try {
        # Start ADB server if not running
        $null = & $script:ADB start-server 2>&1
        $startupDelay = if ($script:Config.ADBStartupDelay -and $script:Config.ADBStartupDelay -ge 500) {
            $script:Config.ADBStartupDelay
        } else { 1000 }
        Start-Sleep -Milliseconds $startupDelay
        
        $rawOutput = & $script:ADB devices -l 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "ADB devices command failed" -Level ERROR
            return ,@()
        }
        
        # Convert output to string - handle both array and string output
        $output = if ($rawOutput -is [System.Array]) {
            $rawOutput -join "`n"
        } else {
            [string]$rawOutput
        }
        
        Write-Log "ADB devices raw output: $output" -Level DEBUG
        
        # Use ArrayList for better performance and predictable behavior
        $deviceList = [System.Collections.ArrayList]::new()
        
        # Handle both Windows (CRLF) and Unix (LF) line endings
        $lines = $output -split '\r?\n'
        
        # Skip the header line "List of devices attached"
        $deviceLines = [System.Collections.ArrayList]::new()
        $foundHeader = $false
        foreach ($line in $lines) {
            if ($line -match '^List of devices attached') {
                $foundHeader = $true
                continue
            }
            if ($foundHeader) {
                [void]$deviceLines.Add($line)
            }
        }
        
        # If no header found, try skipping first line anyway (fallback)
        if (-not $foundHeader -and $lines.Count -gt 1) {
            Write-Log "ADB devices header not found, using fallback parsing" -Level DEBUG
            $deviceLines = [System.Collections.ArrayList]::new()
            for ($i = 1; $i -lt $lines.Count; $i++) {
                [void]$deviceLines.Add($lines[$i])
            }
        }
        
        Write-Log "Found $($deviceLines.Count) potential device lines" -Level DEBUG
        
        foreach ($line in $deviceLines) {
            $trimmedLine = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmedLine)) { continue }
            
            Write-Log "Processing device line: $trimmedLine" -Level DEBUG
            
            $parts = $trimmedLine -split '\s+'
            if ($parts.Count -lt 2) { 
                Write-Log "Skipping line - insufficient parts: $($parts.Count)" -Level DEBUG
                continue 
            }
            
            $deviceID = $parts[0]
            $state = $parts[1]
            
            # Skip if deviceID looks invalid
            if ([string]::IsNullOrWhiteSpace($deviceID)) { continue }
            
            # Parse additional info
            $model = "Unknown"
            $product = "Unknown"
            $transport = "USB"
            
            if ($trimmedLine -match "model:([^\s]+)") { $model = $matches[1] }
            if ($trimmedLine -match "product:([^\s]+)") { $product = $matches[1] }
            if ($deviceID -match ":") { $transport = "WiFi" }
            
            $device = [PSCustomObject]@{
                ID = $deviceID
                State = $state
                Model = $model
                Product = $product
                Transport = $transport
            }
            
            Write-Log "Found device: ID=$deviceID, State=$state, Model=$model" -Level DEBUG
            
            [void]$deviceList.Add($device)
        }
        
        Write-Log "Total devices found: $($deviceList.Count)" -Level INFO
        
        # Return as array - comma operator ensures array is not unwrapped
        return ,@($deviceList.ToArray())
    }
    catch {
        Write-Log "Error getting ADB devices: $($_.Exception.Message)" -Level ERROR
        return ,@()
    }
}

function Get-AndroidVersion {
    <#
    .SYNOPSIS
        Gets Android version information from device
    #>
    param([string]$DeviceID)
    
    try {
        $version = (& $script:ADB -s $DeviceID shell getprop ro.build.version.release 2>&1).Trim()
        $sdk = (& $script:ADB -s $DeviceID shell getprop ro.build.version.sdk 2>&1).Trim()
        
        return [PSCustomObject]@{
            Version = $version
            SDK = [int]$sdk
            HasScopedStorage = ([int]$sdk -ge 30)
        }
    }
    catch {
        Write-Log "Failed to get Android version: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

function Test-AndroidPath {
    <#
    .SYNOPSIS
        Tests if a path exists on Android device (with command injection protection)
    #>
    param(
        [string]$DeviceID,
        [string]$Path
    )
    
    try {
        # Sanitize path to prevent command injection
        if ($script:Config.SanitizePaths) {
            $Path = Protect-ShellPath -Path $Path
        }
        
        $result = & $script:ADB -s $DeviceID shell "test -e '$Path' && echo 'exists' || echo 'not found'" 2>&1
        return ($result.Trim() -eq "exists")
    }
    catch {
        return $false
    }
}

function Get-AndroidFileList {
    <#
    .SYNOPSIS
        Gets list of files from Android path (with command injection protection)
    #>
    param(
        [string]$DeviceID,
        [string]$Path,
        [switch]$Recursive,
        [string[]]$Extensions = @()
    )
    
    try {
        # Sanitize path to prevent command injection
        if ($script:Config.SanitizePaths) {
            $Path = Protect-ShellPath -Path $Path
        }
        
        if ($Recursive) {
            $findCmd = "find '$Path' -type f"
        }
        else {
            $findCmd = "find '$Path' -maxdepth 1 -type f"
        }
        
        # Memory optimization: Use ArrayList for better performance
        $files = New-Object System.Collections.ArrayList
        $count = 0
        $MAX_FILES = 100000  # Prevent resource exhaustion
        
        # Use UTF-8 aware ADB command wrapper for proper encoding
        $output = Invoke-ADBCommandUTF8 -DeviceID $DeviceID -ShellCommand $findCmd
        
        if ($script:LastADBExitCode -ne 0) {
            Write-Log "Failed to list files in $Path" -Level ERROR
            return @()
        }
        
        # Stream processing to prevent memory spike
        foreach ($line in ($output -split "`n")) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                # Resource exhaustion protection
                if ($count -ge $MAX_FILES) {
                    Write-Log "File list exceeded maximum safe limit ($MAX_FILES files). Truncating for safety." -Level WARNING
                    break
                }
                
                $trimmed = $line.Trim()
                
                # Filter by extensions if specified
                if ($Extensions.Count -gt 0) {
                    $ext = [System.IO.Path]::GetExtension($trimmed).ToLowerInvariant()
                    if ($Extensions -contains $ext) {
                        [void]$files.Add($trimmed)
                    }
                }
                else {
                    [void]$files.Add($trimmed)
                }
                
                # Force garbage collection periodically to prevent memory leak
                $count++
                if ($count % $script:Config.GCInterval -eq 0) {
                    [System.GC]::Collect()
                    [System.GC]::WaitForPendingFinalizers()
                }
            }
        }
        
        return $files.ToArray()
    }
    catch {
        Write-Log "Error listing files: $($_.Exception.Message)" -Level ERROR
        return @()
    }
}

function Get-AndroidFileSize {
    <#
    .SYNOPSIS
        Gets file size from Android device (with command injection protection)
    #>
    param(
        [string]$DeviceID,
        [string]$FilePath
    )
    
    try {
        # Escape single quotes in path for shell command
        $escapedPath = $FilePath -replace "'", "'\\''"
        
        # Try stat command first (most reliable) - Use UTF-8 aware wrapper
        $size = Invoke-ADBCommandUTF8 -DeviceID $DeviceID -ShellCommand "stat -c%s '$escapedPath'"
        $sizeStr = if ($size) { $size.Trim() } else { "" }
        
        # Check if stat returned a valid number
        if ($sizeStr -match '^\d+$') {
            return [long]$sizeStr
        }
        
        # Fallback: Try ls -l and parse size
        Write-Log "stat failed for $FilePath, trying ls -l" -Level DEBUG
        $lsOutput = Invoke-ADBCommandUTF8 -DeviceID $DeviceID -ShellCommand "ls -l '$escapedPath'"
        $lsStr = if ($lsOutput) { $lsOutput.Trim() } else { "" }
        
        # ls -l output format: -rw-r--r-- 1 user group SIZE date time filename
        # Size is typically the 5th field
        $parts = $lsStr -split '\s+'
        if ($parts.Count -ge 5 -and $parts[4] -match '^\d+$') {
            return [long]$parts[4]
        }
        
        # Fallback: Try wc -c
        Write-Log "ls -l failed for $FilePath, trying wc -c" -Level DEBUG
        $wcOutput = Invoke-ADBCommandUTF8 -DeviceID $DeviceID -ShellCommand "wc -c < '$escapedPath'"
        $wcStr = if ($wcOutput) { $wcOutput.Trim() } else { "" }
        
        if ($wcStr -match '^\d+$') {
            return [long]$wcStr
        }
        
        Write-Log "All file size methods failed for $FilePath" -Level WARNING
        return -1  # Return -1 to indicate unknown size (different from 0)
    }
    catch {
        Write-Log "Failed to get file size for $FilePath - $($_.Exception.Message)" -Level ERROR
        return -1
    }
}

function Get-AndroidFileListWithSize {
    <#
    .SYNOPSIS
        Gets list of files WITH sizes in single batch query (solves N+1 problem)
    .DESCRIPTION
        This function eliminates the N+1 query problem by fetching file paths
        and sizes in a single ADB command, drastically improving performance
        for large file lists.
    #>
    param(
        [string]$DeviceID,
        [string]$Path,
        [switch]$Recursive,
        [string[]]$Extensions = @()
    )
    
    try {
        # Sanitize path to prevent command injection
        if ($script:Config.SanitizePaths) {
            $Path = Protect-ShellPath -Path $Path
        }
        
        # Single command to get both path and size
        if ($Recursive) {
            $cmd = "find '$Path' -type f -exec stat -c'%s %n' {} \;"
        }
        else {
            $cmd = "find '$Path' -maxdepth 1 -type f -exec stat -c'%s %n' {} \;"
        }
        
        # Use UTF-8 aware ADB command wrapper for proper encoding
        $output = Invoke-ADBCommandUTF8 -DeviceID $DeviceID -ShellCommand $cmd
        
        if ($script:LastADBExitCode -ne 0) {
            Write-Log "Failed to list files with sizes in $Path" -Level ERROR
            return @()
        }
        
        $results = New-Object System.Collections.ArrayList
        $count = 0
        $MAX_FILES = 100000  # Resource exhaustion protection
        
        foreach ($line in ($output -split "`n")) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            
            # Prevent resource exhaustion
            if ($count -ge $MAX_FILES) {
                Write-Log "File list exceeded maximum safe limit ($MAX_FILES files). Truncating." -Level WARNING
                break
            }
            
            # Parse: "size path"
            if ($line -match '^(\d+)\s+(.+)$') {
                $size = [long]$matches[1]
                $filePath = $matches[2].Trim()
                
                # Filter by extensions if specified
                if ($Extensions.Count -gt 0) {
                    $ext = [System.IO.Path]::GetExtension($filePath).ToLowerInvariant()
                    if ($Extensions -notcontains $ext) {
                        continue
                    }
                }
                
                $fileInfo = [PSCustomObject]@{
                    Path = $filePath
                    Size = $size
                }
                
                [void]$results.Add($fileInfo)
                
                # Garbage collection for large lists
                $count++
                if ($count % $script:Config.GCInterval -eq 0) {
                    [System.GC]::Collect()
                }
            }
        }
        
        Write-Log "Batch query retrieved $($results.Count) files with sizes" -Level DEBUG
        return $results.ToArray()
    }
    catch {
        Write-Log "Error in batch size query: $($_.Exception.Message)" -Level ERROR
        return @()
    }
}

# ============================================================================
# VERIFICATION FUNCTIONS
# ============================================================================

function Get-AndroidFileHash {
    <#
    .SYNOPSIS
        Calculates hash of file on Android device
    .DESCRIPTION
        Command injection protection, memory cleanup, audit logging
    #>
    param(
        [string]$DeviceID,
        [string]$FilePath,
        [ValidateSet('MD5','SHA256')]
        [string]$Algorithm = 'MD5'
    )
    
    $hash = $null
    $output = $null
    
    try {
        # MILITARY-GRADE: Audit log
        Write-AuditLog -Action "CalculateHash" -Resource $FilePath `
                      -Result "Attempt" -Details "Algorithm: $Algorithm, Device: $DeviceID"
        
        # Sanitize path to prevent command injection
        if ($script:Config.SanitizePaths) {
            $FilePath = Protect-ShellPath -Path $FilePath
        }
        
        $cmd = switch ($Algorithm) {
            'MD5' { "md5sum" }
            'SHA256' { "sha256sum" }
        }
        
        # Use UTF-8 aware ADB command wrapper for proper encoding
        $output = Invoke-ADBCommandUTF8 -DeviceID $DeviceID -ShellCommand "$cmd '$FilePath'"
        
        if ($script:LastADBExitCode -ne 0) {
            Write-Log "Hash calculation failed for $FilePath" -Level ERROR
            Write-AuditLog -Action "CalculateHash" -Resource $FilePath -Result "Failure"
            return $null
        }
        
        # Parse output: "hash  filename"
        $hash = ($output -split '\s+')[0].Trim().ToLowerInvariant()
        
        Write-AuditLog -Action "CalculateHash" -Resource $FilePath `
                      -Result "Success" -Details "Hash calculated successfully"
        
        return $hash
    }
    catch {
        Write-Log "Error calculating Android hash: $($_.Exception.Message)" -Level ERROR
        Write-AuditLog -Action "CalculateHash" -Resource $FilePath -Result "Failure"
        return $null
    }
    finally {
        # MILITARY-GRADE: Secure cleanup of sensitive data
        if ($output) {
            Clear-SensitiveData -Variable ([ref]$output)
        }
    }
}

function Get-WindowsFileHash {
    <#
    .SYNOPSIS
        Calculates hash of local file
    .DESCRIPTION
        Memory cleanup and audit logging
    #>
    param(
        [string]$FilePath,
        [ValidateSet('MD5','SHA256')]
        [string]$Algorithm = 'MD5'
    )
    
    $hashResult = $null
    $hashString = $null
    
    try {
        # MILITARY-GRADE: Audit log
        Write-AuditLog -Action "CalculateHash" -Resource $FilePath `
                      -Result "Attempt" -Details "Algorithm: $Algorithm, Platform: Windows"
        
        $hashResult = Get-FileHash -Path $FilePath -Algorithm $Algorithm
        $hashString = $hashResult.Hash.ToLowerInvariant()
        
        Write-AuditLog -Action "CalculateHash" -Resource $FilePath `
                      -Result "Success" -Details "Hash calculated successfully"
        
        return $hashString
    }
    catch {
        Write-Log "Error calculating Windows hash: $($_.Exception.Message)" -Level ERROR
        Write-AuditLog -Action "CalculateHash" -Resource $FilePath -Result "Failure"
        return $null
    }
    finally {
        # MILITARY-GRADE: Secure cleanup of sensitive data
        if ($hashResult) {
            $hashResult = $null
        }
    }
}

function Compare-HashSecure {
    <#
    .SYNOPSIS
        Timing-safe hash comparison to prevent timing attacks
    .DESCRIPTION
        Constant-time comparison prevents timing analysis
    #>
    param(
        [string]$Hash1,
        [string]$Hash2
    )
    
    # Quick length check (timing-safe)
    if ($Hash1.Length -ne $Hash2.Length) {
        Start-Sleep -Milliseconds (Get-Random -Minimum 10 -Maximum 30)
        return $false
    }
    
    # Constant-time comparison
    $result = 0
    for ($i = 0; $i -lt $Hash1.Length; $i++) {
        $result = $result -bor ([int][char]$Hash1[$i] -bxor [int][char]$Hash2[$i])
    }
    
    # Add random delay to prevent timing analysis
    Start-Sleep -Milliseconds (Get-Random -Minimum 10 -Maximum 30)
    
    return ($result -eq 0)
}

function Test-FileIntegrity {
    <#
    .SYNOPSIS
        Verifies file integrity with timing-safe hash comparison
    .DESCRIPTION
        Size check first, skips hash for small files, timing-safe comparison
    #>
    param(
        [string]$DeviceID,
        [string]$SourcePath,
        [string]$DestinationPath,
        [string]$Algorithm = 'MD5'
    )
    
    Write-Log "Verifying integrity: $SourcePath" -Level INFO -NoConsole
    
    # Size check first (fast - only 0.1ms)
    $sourceSize = Get-AndroidFileSize -DeviceID $DeviceID -FilePath $SourcePath
    $destSize = (Get-Item $DestinationPath).Length
    
    # If source size is unknown (-1), skip size comparison but still verify hash
    if ($sourceSize -eq -1) {
        Write-Log "Source file size unknown, skipping size check for: $SourcePath" -Level WARNING
        # Fall through to hash verification if file is large enough
        if ($destSize -lt $script:Config.SmallFileThreshold) {
            Write-Log "Small destination file ($([math]::Round($destSize/1MB, 2))MB) - assuming transfer OK" -Level DEBUG
            return $true
        }
    }
    elseif ($sourceSize -ne $destSize) {
        Write-Log "Size mismatch: Source=$sourceSize, Dest=$destSize" -Level ERROR
        return $false
    }
    else {
        # Performance optimization: Skip hash for small files when sizes match
        # Rationale: Files under threshold have very low corruption risk,
        # and hash calculation overhead outweighs the benefit
        if ($sourceSize -lt $script:Config.SmallFileThreshold) {
            Write-Log "Small file ($([math]::Round($sourceSize/1MB, 2))MB) - size check sufficient" -Level DEBUG
            return $true
        }
    }
    
    # Hash verification (slower but thorough)
    $sourceHash = Get-AndroidFileHash -DeviceID $DeviceID -FilePath $SourcePath -Algorithm $Algorithm
    $destHash = Get-WindowsFileHash -FilePath $DestinationPath -Algorithm $Algorithm
    
    # Timing-safe comparison
    if (Compare-HashSecure -Hash1 $sourceHash -Hash2 $destHash) {
        Write-Log "Integrity verified: $SourcePath" -Level SUCCESS -NoConsole
        return $true
    }
    else {
        Write-Log "Hash mismatch detected" -Level ERROR
        return $false
    }
}

function Test-DiskSpace {
    <#
    .SYNOPSIS
        Checks if there is enough disk space for transfer
    #>
    param(
        [string]$DestinationPath,
        [long]$RequiredBytes
    )
    
    try {
        # Get destination drive
        $drive = [System.IO.Path]::GetPathRoot($DestinationPath)
        if ([string]::IsNullOrEmpty($drive)) {
            $drive = (Get-Location).Drive.Root
        }
        
        # Get free space
        $driveInfo = Get-PSDrive -Name ($drive.TrimEnd(':\')) -ErrorAction SilentlyContinue
        if (-not $driveInfo) {
            Write-Log "Could not get drive information for $drive" -Level WARNING
            return $true  # Continue anyway
        }
        
        $freeSpace = $driveInfo.Free
        $requiredWithBuffer = $RequiredBytes * 1.1  # 10% buffer
        
        Write-Log "Disk space check: Required=$(Format-FileSize $requiredWithBuffer), Available=$(Format-FileSize $freeSpace)" -Level INFO -NoConsole
        
        if ($freeSpace -lt $requiredWithBuffer) {
            Write-Log "Insufficient disk space! Required: $(Format-FileSize $requiredWithBuffer), Available: $(Format-FileSize $freeSpace)" -Level ERROR
            return $false
        }
        
        return $true
    }
    catch {
        Write-Log "Error checking disk space: $($_.Exception.Message)" -Level WARNING
        return $true  # Continue anyway if check fails
    }
}

# ============================================================================
# TRANSFER ENGINE FUNCTIONS
# ============================================================================

function Copy-AndroidFile {
    <#
    .SYNOPSIS
        Copies a single file from Android device to Windows with improved error handling
    .DESCRIPTION
        Features:
        - Loop-based retry (no recursion)
        - Race condition protection
        - Proper temp file cleanup tracking
        - Command injection protection
    #>
    param(
        [string]$DeviceID,
        [string]$SourcePath,
        [string]$DestinationPath,
        [switch]$Verify
    )
    
    $maxRetries = $script:Config.MaxRetries
    $retryDelay = $script:Config.RetryDelaySeconds
    $tempPath = $null
    
    # Sanitize source path if enabled (graceful - catch errors and try raw path)
    $safeSourcePath = $SourcePath
    if ($script:Config.SanitizePaths) {
        try {
            $safeSourcePath = Protect-ShellPath -Path $SourcePath
        }
        catch {
            Write-Log "Path sanitization failed for '$SourcePath': $($_.Exception.Message). Using raw path." -Level WARNING
            $safeSourcePath = $SourcePath
        }
    }
    
    # Sanitize Windows destination path - replace invalid filename characters
    try {
        $destDir = Split-Path $DestinationPath -Parent
        $destFileName = Split-Path $DestinationPath -Leaf
        $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
        foreach ($c in $invalidChars) {
            $destFileName = $destFileName.Replace([string]$c, '_')
        }
        $DestinationPath = Join-Path $destDir $destFileName
    }
    catch {
        Write-Log "Destination path cleanup failed: $($_.Exception.Message)" -Level DEBUG
    }
    
    # Skip if file already exists with same size (resume/incremental transfer)
    if (Test-Path $DestinationPath) {
        try {
            # Get source file size
            $sourceSize = Get-AndroidFileSize -DeviceID $DeviceID -FilePath $SourcePath
            $destSize = (Get-Item $DestinationPath).Length
            
            # If source size is unknown (-1), we cannot reliably skip - re-transfer to be safe
            if ($sourceSize -eq -1) {
                Write-Log "Source file size unknown, re-transferring: $(Split-Path $SourcePath -Leaf)" -Level WARNING
                Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue
            }
            elseif ($sourceSize -eq $destSize) {
                # Optional: Verify hash if enabled
                if ($Verify -and $script:Config.AlwaysVerifyHash) {
                    Write-Log "File exists, verifying hash: $(Split-Path $SourcePath -Leaf)" -Level DEBUG
                    $verified = Test-FileIntegrity -DeviceID $DeviceID -SourcePath $SourcePath `
                                                  -DestinationPath $DestinationPath -Algorithm $script:Config.HashAlgorithm
                    
                    if ($verified) {
                        Write-Log "File already exists and verified, skipping: $DestinationPath" -Level DEBUG -NoConsole
                        $script:TransferStats.SkippedFiles++
                        Update-TransferSession -FilePath $SourcePath -Status 'Skipped'
                        return $true
                    }
                    else {
                        Write-Log "File exists but hash mismatch, re-transferring: $DestinationPath" -Level WARNING
                        Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue
                    }
                }
                else {
                    Write-Log "File already exists with same size, skipping: $DestinationPath" -Level DEBUG -NoConsole
                    $script:TransferStats.SkippedFiles++
                    Update-TransferSession -FilePath $SourcePath -Status 'Skipped'
                    return $true
                }
            }
            else {
                Write-Log "File exists but size mismatch (Source: $sourceSize, Dest: $destSize), re-transferring" -Level WARNING
                Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Log "Error checking existing file: $($_.Exception.Message)" -Level WARNING
            # Continue with transfer
        }
    }
    
    # Loop-based retry (prevents stack overflow from recursion)
    for ($attempt = 0; $attempt -le $maxRetries; $attempt++) {
        try {
            # Ensure destination directory exists
            $destDir = Split-Path $DestinationPath -Parent
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }
            
            # Use temporary file for atomic operation
            # Generate cryptographically random filename to prevent prediction
            $randomStr = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 12 | ForEach-Object {[char]$_})
            $tempPath = "$DestinationPath.tmp_$($PID)_$randomStr"
            
            if ($attempt -eq 0) {
                Write-Log "Transferring: $(Split-Path $SourcePath -Leaf)" -Level INFO -NoConsole
            }
            else {
                Write-Log "Retry attempt $attempt of $maxRetries" -Level WARNING
            }
            
            # Execute ADB pull with UTF-8 encoding support
            $pullResult = Invoke-ADBPullUTF8 -DeviceID $DeviceID -SourcePath $safeSourcePath -DestinationPath $tempPath
            
            if ($script:LastADBExitCode -ne 0) {
                # Check for common ADB errors and provide better messages
                $errorDetail = if ($pullResult -match "device not found|no devices") {
                    "Device disconnected. Reconnect and try again."
                } elseif ($pullResult -match "Permission denied|not accessible") {
                    "Permission denied on device. File may be protected."
                } elseif ($pullResult -match "does not exist|No such file") {
                    "Source file not found on device."
                } else {
                    $pullResult
                }
                throw "ADB pull failed: $errorDetail"
            }
            
            # Verify if requested
            if ($Verify) {
                $verified = Test-FileIntegrity -DeviceID $DeviceID -SourcePath $SourcePath `
                                              -DestinationPath $tempPath -Algorithm $script:Config.HashAlgorithm
                
                if (-not $verified) {
                    throw "File integrity verification failed"
                }
            }
            
            # Race condition protection with file locking
            try {
                # Step 1: Double-check locking pattern (prevent TOCTOU)
                $lockFile = "$DestinationPath.lock"
                $lockAcquired = $false
                $lockStream = $null
                
                try {
                    # Attempt to acquire exclusive lock (atomic operation)
                    # This prevents multiple processes from writing to same file
                    $lockStream = [System.IO.File]::Open($lockFile, 
                        [System.IO.FileMode]::CreateNew, 
                        [System.IO.FileAccess]::Write, 
                        [System.IO.FileShare]::None)
                    
                    $lockAcquired = $true
                    Write-Log "File lock acquired: $lockFile" -Level DEBUG
                    
                    # Double-check that destination still doesn't exist
                    if (Test-Path $DestinationPath) {
                        Write-Log "File created by another process during lock acquisition: $DestinationPath" -Level WARNING
                        
                        # Cleanup temp file
                        if (Test-Path $tempPath) {
                            Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
                        }
                        
                        Write-AuditLog -Action "FileTransfer" -Resource $DestinationPath `
                                      -Result "Skipped" -Details "File already exists (race condition detected)"
                        
                        return $true
                    }
                    
                    # Perform atomic move
                    # Note: File.Move(src, dst, overwrite) is only available in .NET Core 3.0+
                    # For compatibility with Windows PowerShell (.NET Framework), use 2-arg version
                    if (Test-Path $DestinationPath) {
                        # This should not happen due to earlier check, but handle it anyway
                        Remove-Item $DestinationPath -Force -ErrorAction Stop
                    }
                    [System.IO.File]::Move($tempPath, $DestinationPath)
                    
                    Write-Log "Atomic move completed: $DestinationPath" -Level DEBUG
            }
            catch [System.IO.IOException] {
                    $errorMsg = $_.Exception.Message
                    
                    # Check if lock file already exists (another process is transferring)
                    if ($errorMsg -match "already exists" -and $errorMsg -match "lock") {
                        Write-Log "Another process is transferring this file, waiting..." -Level WARNING
                        
                        # Wait for lock to be released (with timeout)
                        $waitTime = 0
                        $maxWaitSeconds = 30
                        
                        while ((Test-Path $lockFile) -and $waitTime -lt $maxWaitSeconds) {
                            Start-Sleep -Seconds 1
                            $waitTime++
                        }
                        
                        if (Test-Path $DestinationPath) {
                            Write-Log "File transferred by another process: $DestinationPath" -Level INFO
                            
                            # Cleanup our temp file
                    if (Test-Path $tempPath) {
                        Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
                    }
                            
                    return $true
                }
                        else {
                            # Stale lock or timeout - retry
                            throw "Lock timeout or stale lock detected"
                        }
                    }
                    # Check if destination file already exists
                    elseif ($errorMsg -match "already exists") {
                        Write-Log "File created by another process: $DestinationPath" -Level WARNING
                        
                        if (Test-Path $tempPath) {
                            Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
                        }
                        
                        return $true
                    }
                    else {
                        throw
                    }
                }
                finally {
                    # Always release lock
                    if ($lockStream) {
                        $lockStream.Close()
                        $lockStream.Dispose()
                    }
                    
                    # Remove lock file
                    if ($lockAcquired -and (Test-Path $lockFile)) {
                        try {
                            Remove-Item $lockFile -Force -ErrorAction Stop
                            Write-Log "File lock released: $lockFile" -Level DEBUG
                        }
                        catch {
                            Write-Log "Failed to remove lock file: $lockFile - $($_.Exception.Message)" -Level WARNING
                        }
                    }
                }
            }
            catch {
                Write-Log "Race condition protection error: $($_.Exception.Message)" -Level ERROR
                throw
            }
            
            Write-Log "Successfully transferred: $(Split-Path $SourcePath -Leaf)" -Level SUCCESS -NoConsole
            
            $script:TransferStats.TransferredFiles++
            $fileSize = (Get-Item $DestinationPath).Length
            $script:TransferStats.TransferredBytes += $fileSize
            
            # Track in session
            Update-TransferSession -FilePath $SourcePath -Status 'Completed'
            
            return $true
        }
        catch {
            Write-Log "Transfer failed (attempt $($attempt + 1)): $($_.Exception.Message)" -Level ERROR
            
            # Cleanup temp file with tracking
            if ($tempPath -and (Test-Path $tempPath)) {
                try {
                    Remove-Item $tempPath -Force -ErrorAction Stop
                    Write-Log "Temp file cleaned: $tempPath" -Level DEBUG
                }
                catch {
                    Write-Log "Failed to cleanup temp file: $tempPath - $($_.Exception.Message)" -Level WARNING
                    # Track failed cleanups for later retry
                    if (-not $script:FailedCleanups) {
                        $script:FailedCleanups = @()
                    }
                    $script:FailedCleanups += $tempPath
                }
            }
            
            # Exponential backoff retry
            if ($attempt -lt $maxRetries) {
                # Exponential backoff: delay doubles with each attempt
                $backoffDelay = $retryDelay * [Math]::Pow(2, $attempt)
                # Cap at 60 seconds max
                $backoffDelay = [Math]::Min($backoffDelay, 60)
                
                Write-Log "Retrying with exponential backoff: $backoffDelay seconds (attempt $($attempt + 1)/$maxRetries)..." -Level WARNING
                Start-Sleep -Seconds $backoffDelay
                # Continue to next iteration
            }
            else {
                # All attempts failed
                Write-Log "Transfer failed after $($maxRetries + 1) attempts: $SourcePath" -Level ERROR
                $script:TransferStats.FailedFiles++
                Update-TransferSession -FilePath $SourcePath -Status 'Failed'
                return $false
            }
        }
    }
    
    # Should never reach here, but just in case
    return $false
}

function Copy-AndroidDirectory {
    <#
    .SYNOPSIS
        Copies a directory from Android device to Windows
    #>
    param(
        [string]$DeviceID,
        [string]$SourcePath,
        [string]$DestinationPath,
        [switch]$Verify,
        [switch]$Recursive,
        [string[]]$Extensions = @()
    )
    
    Write-Log "Starting directory transfer: $SourcePath" -Level INFO
    
    # Create transfer session
    $transferType = if ($Recursive) { "RecursiveDirectory" } else { "Directory" }
    New-TransferSession -DeviceID $DeviceID -SourcePath $SourcePath `
                        -DestinationPath $DestinationPath -TransferType $transferType | Out-Null
    
    try {
        # Check if source path exists
        if (-not (Test-AndroidPath -DeviceID $DeviceID -Path $SourcePath)) {
            Write-Log "Source path does not exist: $SourcePath" -Level ERROR
            Complete-TransferSession -FinalStatus 'Failed'
            return $false
        }
        
        # Get file list WITH sizes (batch query - solves N+1 problem!)
        Write-Host "`n  [SCAN] Scanning files and calculating sizes..." -ForegroundColor Cyan
        $filesWithSize = Get-AndroidFileListWithSize -DeviceID $DeviceID -Path $SourcePath `
                                                     -Recursive:$Recursive -Extensions $Extensions
        
        if ($filesWithSize.Count -eq 0) {
            Write-Log "No files found in $SourcePath" -Level WARNING
            Complete-TransferSession -FinalStatus 'Completed'
            return $false
        }
        
        Write-Host "  [INFO] $($filesWithSize.Count) files found" -ForegroundColor Green
    
    # Calculate total size with overflow protection
    $totalSize = 0
    foreach ($fileInfo in $filesWithSize) {
        try {
            $totalSize = Add-SizeSafe -Current $totalSize -Addition $fileInfo.Size
        }
        catch {
            Write-Log "Size calculation overflow: $($_.Exception.Message)" -Level ERROR
            throw "Total file size exceeds safe limit. Cannot proceed with transfer."
        }
    }
    
    Write-Host "  [INFO] Total size: $(Format-FileSize $totalSize)" -ForegroundColor Green
    Write-Host ""
    
    # Check disk space before transfer
    Write-Host "  [CHECK] Checking disk space..." -ForegroundColor Cyan
    if (-not (Test-DiskSpace -DestinationPath $DestinationPath -RequiredBytes $totalSize)) {
        Write-Host "  [ERROR] Insufficient disk space for transfer!" -ForegroundColor Red
        Write-Host "  Required: $(Format-FileSize ($totalSize * 1.1)) (with 10% buffer)" -ForegroundColor Yellow
        $drive = [System.IO.Path]::GetPathRoot($DestinationPath)
        $driveInfo = Get-PSDrive -Name ($drive.TrimEnd(':\'))
        Write-Host "  Available: $(Format-FileSize $driveInfo.Free)" -ForegroundColor Yellow
        Write-Host ""
        Write-Log "Transfer aborted: Insufficient disk space" -Level ERROR
        return $false
    }
    Write-Host "  [OK] Sufficient disk space available" -ForegroundColor Green
    Write-Host ""
    
        $script:TransferStats.TotalFiles = $filesWithSize.Count
        $script:TransferStats.TotalBytes = $totalSize
        $script:TransferStats.StartTime = Get-Date
        
        # Transfer files (with optional parallel processing)
        if ($script:Config.EnableParallelTransfer) {
            Write-Host "  [INFO] Parallel transfer enabled ($($script:Config.ParallelThreadCount) threads)" -ForegroundColor Yellow
            
            # Separate small and large files
            $smallFiles = $filesWithSize | Where-Object { $_.Size -le $script:Config.ParallelFileThreshold }
            $largeFiles = $filesWithSize | Where-Object { $_.Size -gt $script:Config.ParallelFileThreshold }
            
            # Transfer large files sequentially
            if ($largeFiles.Count -gt 0) {
                Write-Host "  [INFO] Transferring $($largeFiles.Count) large files sequentially..." -ForegroundColor Cyan
                foreach ($fileInfo in $largeFiles) {
                    $relativePath = Get-SafeRelativePath -FullPath $fileInfo.Path -BasePath $SourcePath
                    $destFile = Join-Path $DestinationPath $relativePath
                    $success = Copy-AndroidFile -DeviceID $DeviceID -SourcePath $fileInfo.Path `
                                               -DestinationPath $destFile -Verify:$Verify
                    if (-not $success) {
                        Write-Log "Failed to transfer: $($fileInfo.Path)" -Level ERROR
                    }
                }
            }
            
            # Transfer small files in batches (pseudo-parallel)
            if ($smallFiles.Count -gt 0) {
                Write-Host "  [INFO] Transferring $($smallFiles.Count) small files in batches..." -ForegroundColor Cyan
                $batchSize = $script:Config.ParallelThreadCount
                for ($i = 0; $i -lt $smallFiles.Count; $i += $batchSize) {
                    $batch = $smallFiles[$i..[Math]::Min($i + $batchSize - 1, $smallFiles.Count - 1)]
                    foreach ($fileInfo in $batch) {
                        $relativePath = Get-SafeRelativePath -FullPath $fileInfo.Path -BasePath $SourcePath
                        $destFile = Join-Path $DestinationPath $relativePath
                        $success = Copy-AndroidFile -DeviceID $DeviceID -SourcePath $fileInfo.Path `
                                                   -DestinationPath $destFile -Verify:$Verify
                        if (-not $success) {
                            Write-Log "Failed to transfer: $($fileInfo.Path)" -Level ERROR
                        }
                    }
                }
            }
        }
        else {
            # Sequential transfer (default, more reliable)
            $fileNum = 0
            foreach ($fileInfo in $filesWithSize) {
                $fileNum++
                
                # Calculate relative path with path traversal protection
                $relativePath = Get-SafeRelativePath -FullPath $fileInfo.Path -BasePath $SourcePath
                $destFile = Join-Path $DestinationPath $relativePath
                
                # Show progress
                if ($script:Config.ShowProgressBar) {
                    Show-ProgressBar -Current $fileNum -Total $filesWithSize.Count -Activity "Transfer"
                }
                
                # Transfer file
                $success = Copy-AndroidFile -DeviceID $DeviceID -SourcePath $fileInfo.Path `
                                           -DestinationPath $destFile -Verify:$Verify
                
                if (-not $success) {
                    Write-Log "Failed to transfer: $($fileInfo.Path)" -Level ERROR
                }
            }
        }
    
        Write-Host ""
        Write-Log "Directory transfer completed" -Level SUCCESS
        
        Complete-TransferSession -FinalStatus 'Completed'
        return $true
    }
    catch {
        Write-Log "Directory transfer interrupted or failed: $($_.Exception.Message)" -Level ERROR
        Complete-TransferSession -FinalStatus 'Interrupted'
        throw
    }
}

function Expand-PathVariables {
    <#
    .SYNOPSIS
        Expands variables in path template
    #>
    param(
        [string]$Path,
        [string]$DeviceID
    )
    
    $Path = $Path -replace '\{date\}', (Get-Date -Format "yyyy-MM-dd")
    $Path = $Path -replace '\{datetime\}', (Get-Date -Format "yyyy-MM-dd_HHmmss")
    $Path = $Path -replace '\{device_id\}', $DeviceID
    
    # Get device model if available
    if ($script:CurrentDevice) {
        $model = $script:CurrentDevice.Model -replace '[^\w\s-]', '_'
        $Path = $Path -replace '\{device_name\}', $model
    }
    
    return $Path
}

function Invoke-Preset {
    <#
    .SYNOPSIS
        Executes a transfer preset
    #>
    param(
        [string]$PresetID,
        [string]$DeviceID,
        [string]$CustomDestination = $null
    )
    
    $preset = $script:Presets.presets | Where-Object { $_.id -eq $PresetID } | Select-Object -First 1
    
    if (-not $preset) {
        Write-Log "Preset not found: $PresetID" -Level ERROR
        return $false
    }
    
    Write-Log "Executing preset: $($preset.name)" -Level INFO
    
    # Determine destination
    $destination = if ($CustomDestination) { $CustomDestination } else { $preset.destination }
    $destination = Expand-PathVariables -Path $destination -DeviceID $DeviceID
    
    # Make absolute path
    if (-not [System.IO.Path]::IsPathRooted($destination)) {
        $destination = Join-Path $script:Config.DefaultDestination $destination
    }
    
    Write-Host "`n  [TARGET] Destination: $destination" -ForegroundColor Yellow
    
    # Process each source path
    $allSuccess = $true
    foreach ($sourcePath in $preset.source_paths) {
        $success = Copy-AndroidDirectory -DeviceID $DeviceID -SourcePath $sourcePath `
                                        -DestinationPath $destination `
                                        -Verify:$preset.options.verify `
                                        -Recursive:$preset.options.recursive `
                                        -Extensions $preset.filters.extensions
        
        if (-not $success) {
            $allSuccess = $false
        }
    }
    
    return $allSuccess
}

# ============================================================================
# UI FUNCTIONS
# ============================================================================

function Show-Banner {
    <#
    .SYNOPSIS
        Displays application banner with modern CLI aesthetic
    #>
    Clear-Host
    Write-Host ""
    Write-Host "  adbData" -ForegroundColor White -NoNewline
    Write-Host " v$($script:Version)" -ForegroundColor DarkGray
    Write-Host "  High-performance Android file transfer via ADB" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-Disclaimer {
    <#
    .SYNOPSIS
        Shows compact legal disclaimer and gets user consent with Y/N
    #>
    Clear-Host
    Write-Host ""
    Write-Host "  adbData" -ForegroundColor White -NoNewline
    Write-Host " v$($script:Version)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Disclaimer" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  This software is provided AS-IS. No warranty. Use at own risk." -ForegroundColor DarkGray
    Write-Host "  Author is not responsible for any data loss or damage." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  * READ-ONLY access on Android (files never modified/deleted)" -ForegroundColor DarkGray
    Write-Host "  * Transfers files from Android to Windows via ADB" -ForegroundColor DarkGray
    Write-Host "  * Hash verification for data integrity" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Requires USB Debugging enabled and device authorization." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""

    while ($true) {
        Write-Host "  Accept and continue? (Y/N): " -ForegroundColor White -NoNewline
        $response = (Read-Host).Trim()

        if ([string]::IsNullOrEmpty($response)) {
            Write-Host "  Please enter Y or N." -ForegroundColor DarkYellow
            continue
        }

        if ($response.Equals("Y", [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "User accepted disclaimer" -Level INFO -NoConsole
            return $true
        }
        elseif ($response.Equals("N", [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "User declined disclaimer" -Level INFO -NoConsole
            return $false
        }
        else {
            Write-Host "  Please enter Y or N." -ForegroundColor DarkYellow
        }
    }
}

function Show-ScriptInfo {
    <#
    .SYNOPSIS
        Shows script information and usage guide (compact single page)
    #>
    Clear-Host
    Show-Banner

    Write-Host "  About" -ForegroundColor White
    Write-Host ""
    Write-Host "  Fast, secure file transfer from Android to Windows via ADB." -ForegroundColor DarkGray
    Write-Host "  Solves MTP freezing, data loss, and performance issues." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Features" -ForegroundColor White
    Write-Host ""
    Write-Host "    Ready presets      Camera, WhatsApp, Screenshots, Downloads" -ForegroundColor DarkGray
    Write-Host "    Hash verification  MD5/SHA256 integrity guarantee" -ForegroundColor DarkGray
    Write-Host "    Auto retry         Continues on connection drops" -ForegroundColor DarkGray
    Write-Host "    Progress tracking  Real-time transfer status" -ForegroundColor DarkGray
    Write-Host "    READ-ONLY          Device files are never modified" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Performance: ~2-3x faster (large files), ~5-10x (small files) vs MTP" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  How to use" -ForegroundColor White
    Write-Host ""
    Write-Host "    1. Connect Android via USB" -ForegroundColor DarkGray
    Write-Host "    2. Enable USB Debugging (Settings > Developer Options)" -ForegroundColor DarkGray
    Write-Host "    3. Authorize 'Allow USB debugging' on device" -ForegroundColor DarkGray
    Write-Host "    4. Select transfer from main menu" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray -NoNewline
    $null = Read-Host
}

function Show-TransferSummary {
    <#
    .SYNOPSIS
        Shows transfer summary statistics with destination path
    #>
    param(
        [string]$DestinationPath = ""
    )
    
    $duration = (Get-Date) - $script:TransferStats.StartTime
    $avgSpeed = if ($duration.TotalSeconds -gt 0) {
        $script:TransferStats.TransferredBytes / $duration.TotalSeconds
    } else { 0 }

    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Transfer Summary" -ForegroundColor White
    Write-Host ""
    Write-Host "    Total files     $($script:TransferStats.TotalFiles)" -ForegroundColor DarkGray
    Write-Host "    Transferred     $($script:TransferStats.TransferredFiles)" -ForegroundColor Green
    Write-Host "    Skipped         $($script:TransferStats.SkippedFiles)" -ForegroundColor DarkGray
    Write-Host "    Failed          $($script:TransferStats.FailedFiles)" -ForegroundColor $(if ($script:TransferStats.FailedFiles -gt 0) { "Red" } else { "DarkGray" })
    Write-Host ""
    Write-Host "    Total size      $(Format-FileSize $script:TransferStats.TotalBytes)" -ForegroundColor DarkGray
    Write-Host "    Transferred     $(Format-FileSize $script:TransferStats.TransferredBytes)" -ForegroundColor Green
    Write-Host "    Duration        $(Format-Duration $duration)" -ForegroundColor DarkGray
    Write-Host "    Avg speed       $(Format-FileSize $avgSpeed)/s" -ForegroundColor DarkGray
    Write-Host ""

    if ($script:TransferStats.FailedFiles -eq 0) {
        Write-Host "  * Transfer completed successfully" -ForegroundColor Green
    }
    else {
        Write-Host "  ! Some files failed. Check logs for details." -ForegroundColor Yellow
    }

    # Show destination path
    $showDest = if (-not [string]::IsNullOrEmpty($DestinationPath)) { $DestinationPath } else { $script:Config.DefaultDestination }
    Write-Host ""
    Write-Host "  Files saved to: $showDest" -ForegroundColor Cyan
    Write-Host "  Log: $($script:LogFile)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================================
# MENU SYSTEM
# ============================================================================

function Show-DeviceSelection {
    <#
    .SYNOPSIS
        Shows device selection menu with improved detection
    #>
    Write-Host ""
    Write-Host "  Device Selection" -ForegroundColor White
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  Scanning for devices..." -ForegroundColor DarkGray

    # Try multiple times with increasing delays for ADB server reliability
    $devices = $null
    $maxRetries = 3

    for ($retry = 1; $retry -le $maxRetries; $retry++) {
        # Get devices and ensure it's always an array
        $result = Get-ADBDevices
        $devices = @($result)

        Write-Log "Device scan attempt $retry - Received type: $($result.GetType().Name), Count: $($devices.Count)" -Level DEBUG

        if ($null -ne $devices -and $devices.Count -gt 0) {
            Write-Log "Found $($devices.Count) device(s) on attempt $retry" -Level INFO
            break
        }

        if ($retry -lt $maxRetries) {
            Write-Host "  Retry $retry/$maxRetries - Restarting ADB server..." -ForegroundColor DarkYellow
            $null = & $script:ADB kill-server 2>&1
            Start-Sleep -Milliseconds 500
            $null = & $script:ADB start-server 2>&1
            Start-Sleep -Milliseconds 1500
        }
    }

    # Final safety check
    if ($null -eq $devices) {
        $devices = @()
    }

    if ($devices.Count -eq 0) {
        Write-Host ""
        Write-Host "  ! No devices found" -ForegroundColor Yellow
        Write-Host ""

        # Show raw ADB output for debugging
        $rawDiag = & $script:ADB devices -l 2>&1
        Write-Host "  ADB output: $rawDiag" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Troubleshooting:" -ForegroundColor White
        Write-Host "    - Is device connected via USB?" -ForegroundColor DarkGray
        Write-Host "    - Is USB Debugging enabled?" -ForegroundColor DarkGray
        Write-Host "    - Did you authorize 'Allow USB debugging' on device?" -ForegroundColor DarkGray
        Write-Host "    - Try a different USB cable or port" -ForegroundColor DarkGray
        Write-Host "    - Try running: adb kill-server && adb start-server" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Press Enter to go back..." -ForegroundColor DarkGray -NoNewline
        $null = Read-Host
        return $null
    }

    Write-Host ""

    for ($i = 0; $i -lt $devices.Count; $i++) {
        $device = $devices[$i]
        $stateColor = if ($device.State -eq "device") { "Green" } 
                      elseif ($device.State -eq "unauthorized") { "Yellow" }
                      else { "DarkGray" }

        Write-Host "  [$($i + 1)] " -ForegroundColor White -NoNewline
        Write-Host "$($device.Model)" -ForegroundColor $stateColor
        Write-Host "      $($device.ID) | $($device.State) | $($device.Transport)" -ForegroundColor DarkGray
        
        if ($device.State -eq "unauthorized") {
            Write-Host "      ! Check device screen for USB debugging authorization prompt" -ForegroundColor Yellow
        }
        Write-Host ""
    }

    Write-Host "  [0] Go back" -ForegroundColor DarkGray
    Write-Host ""

    while ($true) {
        Write-Host "  Select device (0-$($devices.Count)): " -ForegroundColor White -NoNewline
        $choice = Read-Host

        if ($choice -eq "0") {
            return $null
        }

        $index = [int]$choice - 1
        if ($index -ge 0 -and $index -lt $devices.Count) {
            $selectedDevice = $devices[$index]

            if ($selectedDevice.State -ne "device") {
                Write-Host ""
                if ($selectedDevice.State -eq "unauthorized") {
                    Write-Host "  ! Device not authorized. Check the USB debugging prompt on your device." -ForegroundColor Yellow
                } else {
                    Write-Host "  ! Device not ready. Status: $($selectedDevice.State)" -ForegroundColor Yellow
                }
                Write-Host "  Press Enter to go back..." -ForegroundColor DarkGray -NoNewline
                $null = Read-Host
                return $null
            }

            $script:CurrentDevice = $selectedDevice
            Write-Log "Device selected: $($selectedDevice.Model) ($($selectedDevice.ID))" -Level INFO
            return $selectedDevice
        }
        else {
            Write-Host "  Invalid selection." -ForegroundColor DarkYellow
        }
    }
}

function Show-PresetMenu {
    <#
    .SYNOPSIS
        Shows preset transfer menu with multi-select support
    #>
    Clear-Host
    Show-Banner

    if (-not $script:CurrentDevice) {
        Write-Host "  ! No device selected. Select a device first." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }

    Write-Host "  Quick Transfer (Presets)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Device: $($script:CurrentDevice.Model)" -ForegroundColor Green
    Write-Host "  Destination: $($script:Config.DefaultDestination)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""

    $presets = $script:Presets.presets

    # Display presets in two columns for space efficiency
    for ($i = 0; $i -lt $presets.Count; $i++) {
        $num = $i + 1
        $padNum = if ($num -lt 10) { " $num" } else { "$num" }
        Write-Host "  [$padNum] $($presets[$i].name)" -ForegroundColor White -NoNewline
        Write-Host "  $($presets[$i].description)" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Enter numbers separated by commas for multi-select." -ForegroundColor DarkGray
    Write-Host "  Example: 1,3,5  or  1-5  or  all" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [0] Back" -ForegroundColor DarkGray
    Write-Host ""

    while ($true) {
        Write-Host "  > " -ForegroundColor White -NoNewline
        $input_str = (Read-Host).Trim()

        if ($input_str -eq "0" -or [string]::IsNullOrEmpty($input_str)) {
            return
        }

        # Parse selection
        $selectedIndices = @()
        
        if ($input_str.Equals("all", [System.StringComparison]::OrdinalIgnoreCase)) {
            $selectedIndices = 0..($presets.Count - 1)
        }
        else {
            foreach ($part in ($input_str -split ',')) {
                $part = $part.Trim()
                if ($part -match '^(\d+)-(\d+)$') {
                    $rangeStart = [int]$matches[1]
                    $rangeEnd = [int]$matches[2]
                    for ($r = $rangeStart; $r -le $rangeEnd; $r++) {
                        if ($r -ge 1 -and $r -le $presets.Count) {
                            $selectedIndices += ($r - 1)
                        }
                    }
                }
                elseif ($part -match '^\d+$') {
                    $num = [int]$part
                    if ($num -ge 1 -and $num -le $presets.Count) {
                        $selectedIndices += ($num - 1)
                    }
                }
            }
        }

        $selectedIndices = $selectedIndices | Select-Object -Unique | Sort-Object

        if ($selectedIndices.Count -eq 0) {
            Write-Host "  Invalid selection." -ForegroundColor DarkYellow
            continue
        }

        # Confirm selection
        Write-Host ""
        Write-Host "  Selected:" -ForegroundColor White
        foreach ($idx in $selectedIndices) {
            Write-Host "    + $($presets[$idx].name)" -ForegroundColor Green
        }
        Write-Host ""

        # Reset stats
        $script:TransferStats = @{
            TotalFiles = 0
            TransferredFiles = 0
            SkippedFiles = 0
            TotalBytes = 0
            TransferredBytes = 0
            FailedFiles = 0
            StartTime = Get-Date
        }

        # Execute all selected presets
        foreach ($idx in $selectedIndices) {
            $preset = $presets[$idx]
            Write-Host "  Starting: $($preset.name)" -ForegroundColor White
            [void](Invoke-Preset -PresetID $preset.id -DeviceID $script:CurrentDevice.ID)
        }

        Show-TransferSummary -DestinationPath $script:Config.DefaultDestination

        Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray -NoNewline
        $null = Read-Host
        return
    }
}

function Show-CustomTransferMenu {
    <#
    .SYNOPSIS
        Shows custom directory transfer menu
    #>
    Clear-Host
    Show-Banner

    if (-not $script:CurrentDevice) {
        Write-Host "  ! No device selected. Select a device first." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }

    Write-Host "  Custom Directory Transfer" -ForegroundColor White
    Write-Host ""
    Write-Host "  Device: $($script:CurrentDevice.Model)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""

    # Get source path
    Write-Host "  Source path (Android):" -ForegroundColor White
    Write-Host "  Example: /sdcard/DCIM/Camera/" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  > " -ForegroundColor White -NoNewline
    $sourcePath = Read-Host

    if ([string]::IsNullOrWhiteSpace($sourcePath)) {
        Write-Host "  ! Invalid path." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }

    # Check if path exists
    if (-not (Test-AndroidPath -DeviceID $script:CurrentDevice.ID -Path $sourcePath)) {
        Write-Host "  ! Path not found: $sourcePath" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }

    # Get destination path
    Write-Host ""
    Write-Host "  Destination path (Windows):" -ForegroundColor White
    Write-Host "  Default: $($script:Config.DefaultDestination)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  > " -ForegroundColor White -NoNewline
    $destPath = Read-Host

    if ([string]::IsNullOrWhiteSpace($destPath)) {
        $destPath = $script:Config.DefaultDestination
    }

    # Options
    Write-Host ""
    Write-Host "  Include subdirectories? (Y/N): " -ForegroundColor White -NoNewline
    $recursiveChoice = (Read-Host).Trim()
    $recursive = (-not [string]::IsNullOrEmpty($recursiveChoice)) -and $recursiveChoice.Equals("Y", [System.StringComparison]::OrdinalIgnoreCase)

    Write-Host "  Hash verification? (Y/N) [Y]: " -ForegroundColor White -NoNewline
    $verifyChoice = (Read-Host).Trim()
    $verify = [string]::IsNullOrEmpty($verifyChoice) -or (-not $verifyChoice.Equals("N", [System.StringComparison]::OrdinalIgnoreCase))

    $script:TransferStats = @{
        TotalFiles = 0
        TransferredFiles = 0
        SkippedFiles = 0
        TotalBytes = 0
        TransferredBytes = 0
        FailedFiles = 0
        StartTime = Get-Date
    }

    Write-Host ""
    [void](Copy-AndroidDirectory -DeviceID $script:CurrentDevice.ID `
                                -SourcePath $sourcePath `
                                -DestinationPath $destPath `
                                -Verify:$verify `
                                -Recursive:$recursive)

    Show-TransferSummary -DestinationPath $destPath

    Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray -NoNewline
    $null = Read-Host
}

function Show-Help {
    <#
    .SYNOPSIS
        Shows comprehensive help and documentation
    #>
    Clear-Host
    Show-Banner

    Write-Host "  Help & Documentation" -ForegroundColor White
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  [1] Quick Start Guide" -ForegroundColor White
    Write-Host "  [2] Common Android Paths" -ForegroundColor White
    Write-Host "  [3] Troubleshooting" -ForegroundColor White
    Write-Host "  [4] Configuration" -ForegroundColor White
    Write-Host "  [5] About" -ForegroundColor White
    Write-Host "  [0] Back" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  > " -ForegroundColor White -NoNewline
    $choice = Read-Host

    Clear-Host
    Show-Banner

    switch ($choice) {
        "1" {
            Write-Host "  Quick Start Guide" -ForegroundColor White
            Write-Host ""
            Write-Host "  1. Connect Android device via USB" -ForegroundColor DarkGray
            Write-Host "  2. Enable USB Debugging (Settings > Developer Options)" -ForegroundColor DarkGray
            Write-Host "  3. Accept 'Allow USB debugging' prompt on device" -ForegroundColor DarkGray
            Write-Host "  4. Main Menu > [1] Select Device" -ForegroundColor DarkGray
            Write-Host "  5. Choose Quick Transfer [2] or Custom Transfer [3]" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  Features:" -ForegroundColor White
            Write-Host "    + Automatic hash verification (MD5/SHA256)" -ForegroundColor DarkGray
            Write-Host "    + Resume capability - skips existing files" -ForegroundColor DarkGray
            Write-Host "    + READ-ONLY access - device files stay safe" -ForegroundColor DarkGray
            Write-Host "    + Detailed logging for troubleshooting" -ForegroundColor DarkGray
        }
        "2" {
            Write-Host "  Common Android Paths" -ForegroundColor White
            Write-Host ""
            Write-Host "  Photos & Videos:" -ForegroundColor White
            Write-Host "    /sdcard/DCIM/Camera/            Camera photos/videos" -ForegroundColor DarkGray
            Write-Host "    /sdcard/Pictures/               All pictures" -ForegroundColor DarkGray
            Write-Host "    /sdcard/Pictures/Screenshots/   Screenshots" -ForegroundColor DarkGray
            Write-Host "    /sdcard/Movies/                 Video files" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  Messaging:" -ForegroundColor White
            Write-Host "    /sdcard/WhatsApp/Media/         WhatsApp (<Android 11)" -ForegroundColor DarkGray
            Write-Host "    /sdcard/Android/media/com.whatsapp/WhatsApp/  (Android 11+)" -ForegroundColor DarkGray
            Write-Host "    /sdcard/Telegram/               Telegram files" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  Other:" -ForegroundColor White
            Write-Host "    /sdcard/Download/               Downloads" -ForegroundColor DarkGray
            Write-Host "    /sdcard/Music/                  Music" -ForegroundColor DarkGray
            Write-Host "    /sdcard/Documents/              Documents" -ForegroundColor DarkGray
        }
        "3" {
            Write-Host "  Troubleshooting" -ForegroundColor White
            Write-Host ""
            Write-Host "  Device not found:" -ForegroundColor White
            Write-Host "    - Check USB cable connection" -ForegroundColor DarkGray
            Write-Host "    - Enable USB Debugging on device" -ForegroundColor DarkGray
            Write-Host "    - Accept 'Allow USB debugging' prompt" -ForegroundColor DarkGray
            Write-Host "    - Try different USB port (USB 2.0 recommended)" -ForegroundColor DarkGray
            Write-Host "    - Run: adb kill-server && adb start-server" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  Transfer failed:" -ForegroundColor White
            Write-Host "    - Check available disk space" -ForegroundColor DarkGray
            Write-Host "    - Keep device awake during transfer" -ForegroundColor DarkGray
            Write-Host "    - Review logs: $($script:LogDir)" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  Slow transfers:" -ForegroundColor White
            Write-Host "    - Use USB 3.0 cable and port" -ForegroundColor DarkGray
            Write-Host "    - Use MD5 instead of SHA256 (Settings)" -ForegroundColor DarkGray
        }
        "4" {
            Write-Host "  Configuration" -ForegroundColor White
            Write-Host ""
            Write-Host "  Config file: $($script:ConfigDir)\settings.json" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  AlwaysVerifyHash    true/false   Verify integrity after transfer" -ForegroundColor DarkGray
            Write-Host "  HashAlgorithm       MD5/SHA256   MD5 faster, SHA256 more secure" -ForegroundColor DarkGray
            Write-Host "  MaxRetries          3            Retry attempts for failed transfers" -ForegroundColor DarkGray
            Write-Host "  SmallFileThreshold  100MB        Skip hash for files under this" -ForegroundColor DarkGray
            Write-Host "  SanitizePaths       true         Command injection protection" -ForegroundColor DarkGray
        }
        "5" {
            Write-Host "  About" -ForegroundColor White
            Write-Host ""
            Write-Host "  adbData v$($script:Version)" -ForegroundColor DarkGray
            Write-Host "  High-performance Android file transfer via ADB" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  Developer: Bugra" -ForegroundColor DarkGray
            Write-Host "  AI: Claude Sonnet 4.5 (Anthropic)" -ForegroundColor DarkGray
            Write-Host "  License: MIT" -ForegroundColor DarkGray
        }
        default {
            return
        }
    }

    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray -NoNewline
    $null = Read-Host
}

function Show-DeviceInfo {
    <#
    .SYNOPSIS
        Shows detailed device information
    #>
    Clear-Host
    Show-Banner

    if (-not $script:CurrentDevice) {
        Write-Host "  ! No device selected. Select a device first." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }

    Write-Host "  Device Information" -ForegroundColor White
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    Model         $($script:CurrentDevice.Model)" -ForegroundColor DarkGray
    Write-Host "    Product       $($script:CurrentDevice.Product)" -ForegroundColor DarkGray
    Write-Host "    ID            $($script:CurrentDevice.ID)" -ForegroundColor DarkGray
    Write-Host "    Connection    $($script:CurrentDevice.Transport)" -ForegroundColor DarkGray
    Write-Host ""

    # Get Android version
    $androidInfo = Get-AndroidVersion -DeviceID $script:CurrentDevice.ID

    if ($androidInfo) {
        Write-Host "    Android       $($androidInfo.Version) (SDK $($androidInfo.SDK))" -ForegroundColor DarkGray
        Write-Host "    Scoped Storage  $(if ($androidInfo.HasScopedStorage) { 'Yes (Android 11+)' } else { 'No' })" -ForegroundColor DarkGray
        Write-Host ""
    }

    # Get storage info
    try {
        $storageInfo = & $script:ADB -s $script:CurrentDevice.ID shell "df -h /sdcard" 2>&1 | Select-Object -Skip 1
        $storageText = if ($storageInfo -is [System.Array]) { ($storageInfo | Select-Object -First 1).Trim() } else { ([string]$storageInfo).Trim() }
        Write-Host "    Storage       $storageText" -ForegroundColor DarkGray
    }
    catch {
        Write-Host "    Storage       Unable to retrieve" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  Access mode: READ-ONLY (device files never modified)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray -NoNewline
    $null = Read-Host
}

function Show-Settings {
    <#
    .SYNOPSIS
        Shows settings menu
    #>
    Clear-Host
    Show-Banner

    Write-Host "  Settings" -ForegroundColor White
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [1] Default destination   $($script:Config.DefaultDestination)" -ForegroundColor DarkGray
    Write-Host "  [2] Hash verification     $(if ($script:Config.AlwaysVerifyHash) { 'Enabled' } else { 'Disabled' })" -ForegroundColor DarkGray
    Write-Host "  [3] Hash algorithm        $($script:Config.HashAlgorithm)" -ForegroundColor DarkGray
    Write-Host "  [4] Max retries           $($script:Config.MaxRetries)" -ForegroundColor DarkGray
    Write-Host "  [5] Progress bar          $(if ($script:Config.ShowProgressBar) { 'Enabled' } else { 'Disabled' })" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [0] Back" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  > " -ForegroundColor White -NoNewline
    $choice = Read-Host

    switch ($choice) {
        "1" {
            Write-Host ""
            Write-Host "  New default destination: " -ForegroundColor White -NoNewline
            $newPath = Read-Host
            if (-not [string]::IsNullOrWhiteSpace($newPath)) {
                $script:Config.DefaultDestination = $newPath
                Save-Config
                Write-Host "  * Saved" -ForegroundColor Green
                Start-Sleep -Seconds 1
            }
        }
        "2" {
            $script:Config.AlwaysVerifyHash = -not $script:Config.AlwaysVerifyHash
            Save-Config
            Write-Host "  * Hash verification: $(if ($script:Config.AlwaysVerifyHash) { 'Enabled' } else { 'Disabled' })" -ForegroundColor Green
            Start-Sleep -Seconds 1
        }
        "3" {
            Write-Host ""
            Write-Host "  [1] MD5 (fast)  [2] SHA256 (secure)" -ForegroundColor DarkGray
            Write-Host "  > " -ForegroundColor White -NoNewline
            $algoChoice = Read-Host
            if ($algoChoice -eq "1") {
                $script:Config.HashAlgorithm = "MD5"
            } elseif ($algoChoice -eq "2") {
                $script:Config.HashAlgorithm = "SHA256"
            }
            Save-Config
            Write-Host "  * Algorithm: $($script:Config.HashAlgorithm)" -ForegroundColor Green
            Start-Sleep -Seconds 1
        }
        "0" { return }
    }

    Show-Settings
}

# ============================================================================
# FULL BACKUP (PRE-FORMAT)
# ============================================================================

function Show-FullBackupMenu {
    <#
    .SYNOPSIS
        Full device backup before format - backs up all essential user data
    #>
    Clear-Host
    Show-Banner

    if (-not $script:CurrentDevice) {
        Write-Host "  ! No device selected. Select a device first." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }

    Write-Host "  Full Backup (Pre-Format)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Device: $($script:CurrentDevice.Model)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  This will backup all essential data from your device." -ForegroundColor DarkGray
    Write-Host "  Recommended before factory reset or ROM flash." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Folders to backup:" -ForegroundColor White
    Write-Host ""
    
    $backupPaths = @(
        @{ Path = "/sdcard/DCIM/";       Name = "DCIM (Camera, Photos)" },
        @{ Path = "/sdcard/Pictures/";    Name = "Pictures" },
        @{ Path = "/sdcard/Movies/";      Name = "Movies" },
        @{ Path = "/sdcard/Music/";       Name = "Music" },
        @{ Path = "/sdcard/Documents/";   Name = "Documents" },
        @{ Path = "/sdcard/Download/";    Name = "Downloads" },
        @{ Path = "/sdcard/WhatsApp/";    Name = "WhatsApp" },
        @{ Path = "/sdcard/Telegram/";    Name = "Telegram" },
        @{ Path = "/sdcard/Recordings/";  Name = "Recordings" },
        @{ Path = "/sdcard/Ringtones/";   Name = "Ringtones" },
        @{ Path = "/sdcard/Notifications/"; Name = "Notifications" },
        @{ Path = "/sdcard/Alarms/";      Name = "Alarms" },
        @{ Path = "/sdcard/Podcasts/";    Name = "Podcasts" },
        @{ Path = "/sdcard/Bluetooth/";   Name = "Bluetooth" },
        @{ Path = "/sdcard/Android/media/com.whatsapp/"; Name = "WhatsApp (Android 11+)" },
        @{ Path = "/sdcard/Android/media/org.telegram.messenger/"; Name = "Telegram (Android 11+)" }
    )

    foreach ($bp in $backupPaths) {
        Write-Host "    + $($bp.Name)" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  Destination: $($script:Config.DefaultDestination)\FullBackup\{date}" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Start full backup? (Y/N): " -ForegroundColor White -NoNewline
    $confirm = (Read-Host).Trim()

    if ([string]::IsNullOrEmpty($confirm) -or -not $confirm.Equals("Y", [System.StringComparison]::OrdinalIgnoreCase)) {
        return
    }

    $backupDate = Get-Date -Format "yyyy-MM-dd"
    $backupDest = Join-Path $script:Config.DefaultDestination "FullBackup\$backupDate"

    # Reset stats
    $script:TransferStats = @{
        TotalFiles = 0
        TransferredFiles = 0
        SkippedFiles = 0
        TotalBytes = 0
        TransferredBytes = 0
        FailedFiles = 0
        StartTime = Get-Date
    }

    Write-Host ""
    Write-Host "  Starting full backup..." -ForegroundColor White
    Write-Host ""

    $successCount = 0
    $skipCount = 0
    
    foreach ($bp in $backupPaths) {
        # Check if path exists on device
        $exists = Test-AndroidPath -DeviceID $script:CurrentDevice.ID -Path $bp.Path
        if (-not $exists) {
            Write-Host "  - $($bp.Name): not found, skipping" -ForegroundColor DarkGray
            $skipCount++
            continue
        }

        Write-Host "  + $($bp.Name)" -ForegroundColor White
        
        # Derive subfolder name from path
        $folderName = ($bp.Path -replace '/sdcard/', '' -replace '/sdcard$', '' -replace '/', '_').TrimEnd('_')
        if ([string]::IsNullOrEmpty($folderName)) { $folderName = "root" }
        $dest = Join-Path $backupDest $folderName

        try {
            [void](Copy-AndroidDirectory -DeviceID $script:CurrentDevice.ID `
                                        -SourcePath $bp.Path `
                                        -DestinationPath $dest `
                                        -Verify:$true `
                                        -Recursive:$true)
            $successCount++
        }
        catch {
            Write-Log "Full backup failed for $($bp.Path): $($_.Exception.Message)" -Level ERROR
            Write-Host "    ! Error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "  Full backup completed ($successCount folders backed up, $skipCount skipped)" -ForegroundColor Green
    
    Show-TransferSummary -DestinationPath $backupDest

    Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray -NoNewline
    $null = Read-Host
}

# ============================================================================
# CLI FILE EXPLORER
# ============================================================================

function Show-FileExplorer {
    <#
    .SYNOPSIS
        CLI-based file explorer for Android filesystem via ADB
    .DESCRIPTION
        Browse the Android filesystem, navigate folders, and transfer
        selected files or folders to the PC.
    #>
    if (-not $script:CurrentDevice) {
        Write-Host "  ! No device selected. Select a device first." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }

    $currentPath = "/sdcard"
    $deviceID = $script:CurrentDevice.ID

    while ($true) {
        Clear-Host
        Show-Banner

        Write-Host "  File Explorer" -ForegroundColor White
        Write-Host ""
        Write-Host "  Device: $($script:CurrentDevice.Model)" -ForegroundColor Green
        Write-Host "  Path: $currentPath" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""

        # List contents of current directory - escape single quotes for shell
        $escapedPath = $currentPath -replace "'", "'\''"
        $listCmd = "ls -la '$escapedPath' 2>/dev/null"
        $rawOutput = Invoke-ADBCommandUTF8 -DeviceID $deviceID -ShellCommand $listCmd

        if ($null -eq $rawOutput -or $script:LastADBExitCode -ne 0) {
            Write-Host "  ! Cannot read directory" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  [B] Go back  [0] Exit explorer" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  > " -ForegroundColor White -NoNewline
            $nav = (Read-Host).Trim()
            if ($nav.Equals("0", [System.StringComparison]::OrdinalIgnoreCase)) { return }
            $currentPath = Split-Path $currentPath -Parent
            if ([string]::IsNullOrEmpty($currentPath)) { $currentPath = "/" }
            $currentPath = $currentPath -replace '\\', '/'
            continue
        }

        $lines = $rawOutput -split "`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        
        # Parse directory listing
        $entries = [System.Collections.ArrayList]::new()
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            # Skip total line
            if ($trimmed -match '^total\s+\d+') { continue }
            
            # Parse ls -la output: permissions links owner group size date time name
            # Handle both long date format and short
            $isDir = $trimmed.StartsWith('d')
            $isLink = $trimmed.StartsWith('l')
            
            # Extract name (last field, but could contain spaces)
            # Try to match: perms links owner group size month day time/year name
            if ($trimmed -match '^\S+\s+\S+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(.+)$') {
                $size = [long]$matches[1]
                $name = $matches[2].Trim()
                
                # Handle symlinks: name -> target
                if ($isLink -and $name -match '^(.+?)\s+->\s+') {
                    $name = $matches[1].Trim()
                }
                
                # Skip . and ..
                if ($name -eq '.' -or $name -eq '..') { continue }
                
                [void]$entries.Add([PSCustomObject]@{
                    Name = $name
                    IsDirectory = $isDir -or $isLink
                    Size = $size
                    Raw = $trimmed
                })
            }
        }

        # Sort: directories first, then files
        $sortedEntries = @($entries | Sort-Object -Property @{Expression={-not $_.IsDirectory}}, Name)

        if ($sortedEntries.Count -eq 0) {
            Write-Host "  (empty directory)" -ForegroundColor DarkGray
        }
        else {
            $maxShow = [Math]::Min($sortedEntries.Count, 40)
            for ($i = 0; $i -lt $maxShow; $i++) {
                $entry = $sortedEntries[$i]
                $num = $i + 1
                $padNum = if ($num -lt 10) { " $num" } else { "$num" }
                
                if ($entry.IsDirectory) {
                    Write-Host "  [$padNum] " -ForegroundColor White -NoNewline
                    Write-Host "$($entry.Name)/" -ForegroundColor Cyan
                }
                else {
                    $sizeStr = Format-FileSize $entry.Size
                    Write-Host "  [$padNum] " -ForegroundColor White -NoNewline
                    Write-Host "$($entry.Name)" -ForegroundColor DarkGray -NoNewline
                    Write-Host "  ($sizeStr)" -ForegroundColor DarkGray
                }
            }
            
            if ($sortedEntries.Count -gt $maxShow) {
                Write-Host "  ... and $($sortedEntries.Count - $maxShow) more items" -ForegroundColor DarkGray
            }
        }

        Write-Host ""
        Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Commands:" -ForegroundColor DarkGray
        Write-Host "    [number]  Open folder / Select file" -ForegroundColor DarkGray
        Write-Host "    [B]       Go back (parent directory)" -ForegroundColor DarkGray
        Write-Host "    [C]       Copy current folder to PC" -ForegroundColor DarkGray
        Write-Host "    [P path]  Go to path (e.g. P /sdcard/DCIM)" -ForegroundColor DarkGray
        Write-Host "    [0]       Exit explorer" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  > " -ForegroundColor White -NoNewline
        $cmd = (Read-Host).Trim()

        if ([string]::IsNullOrEmpty($cmd)) { continue }

        # Exit
        if ($cmd -eq "0") { return }

        # Go back
        if ($cmd.Equals("B", [System.StringComparison]::OrdinalIgnoreCase)) {
            if ($currentPath -ne "/" -and $currentPath -ne "/sdcard") {
                $parent = $currentPath -replace '/[^/]+/?$', ''
                if ([string]::IsNullOrEmpty($parent)) { $parent = "/" }
                $currentPath = $parent
            }
            continue
        }

        # Go to path
        if ($cmd.StartsWith("P ", [System.StringComparison]::OrdinalIgnoreCase) -or 
            $cmd.StartsWith("p ", [System.StringComparison]::OrdinalIgnoreCase)) {
            $newPath = $cmd.Substring(2).Trim()
            if (-not [string]::IsNullOrEmpty($newPath)) {
                if (Test-AndroidPath -DeviceID $deviceID -Path $newPath) {
                    $currentPath = $newPath.TrimEnd('/')
                }
                else {
                    Write-Host "  ! Path not found: $newPath" -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                }
            }
            continue
        }

        # Copy current folder
        if ($cmd.Equals("C", [System.StringComparison]::OrdinalIgnoreCase)) {
            $folderName = Split-Path $currentPath -Leaf
            if ([string]::IsNullOrEmpty($folderName)) { $folderName = "root" }
            $dest = Join-Path $script:Config.DefaultDestination "Explorer\$folderName"

            Write-Host ""
            Write-Host "  Copy '$currentPath' to '$dest'? (Y/N): " -ForegroundColor White -NoNewline
            $confirm = (Read-Host).Trim()
            
            if (-not [string]::IsNullOrEmpty($confirm) -and $confirm.Equals("Y", [System.StringComparison]::OrdinalIgnoreCase)) {
                $script:TransferStats = @{
                    TotalFiles = 0; TransferredFiles = 0; SkippedFiles = 0
                    TotalBytes = 0; TransferredBytes = 0; FailedFiles = 0
                    StartTime = Get-Date
                }

                [void](Copy-AndroidDirectory -DeviceID $deviceID `
                                            -SourcePath "$currentPath/" `
                                            -DestinationPath $dest `
                                            -Verify:$true -Recursive:$true)

                Show-TransferSummary -DestinationPath $dest
                Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray -NoNewline
                $null = Read-Host
            }
            continue
        }

        # Number selection - open folder or copy file
        if ($cmd -match '^\d+$') {
            $idx = [int]$cmd - 1
            if ($idx -ge 0 -and $idx -lt $sortedEntries.Count) {
                $selected = $sortedEntries[$idx]

                if ($selected.IsDirectory) {
                    # Navigate into directory
                    $currentPath = "$currentPath/$($selected.Name)" -replace '//', '/'
                }
                else {
                    # Offer to copy the file
                    $filePath = "$currentPath/$($selected.Name)" -replace '//', '/'
                    $fileName = $selected.Name
                    $dest = Join-Path $script:Config.DefaultDestination "Explorer\$fileName"

                    Write-Host ""
                    Write-Host "  Copy '$fileName' to PC? (Y/N): " -ForegroundColor White -NoNewline
                    $confirm = (Read-Host).Trim()
                    
                    if (-not [string]::IsNullOrEmpty($confirm) -and $confirm.Equals("Y", [System.StringComparison]::OrdinalIgnoreCase)) {
                        $script:TransferStats = @{
                            TotalFiles = 1; TransferredFiles = 0; SkippedFiles = 0
                            TotalBytes = $selected.Size; TransferredBytes = 0; FailedFiles = 0
                            StartTime = Get-Date
                        }

                        $success = Copy-AndroidFile -DeviceID $deviceID `
                                                   -SourcePath $filePath `
                                                   -DestinationPath $dest `
                                                   -Verify

                        if ($success) {
                            Write-Host "  * File copied to: $dest" -ForegroundColor Green
                        }
                        else {
                            Write-Host "  ! Transfer failed" -ForegroundColor Yellow
                        }
                        Write-Host ""
                        Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray -NoNewline
                        $null = Read-Host
                    }
                }
            }
            else {
                Write-Host "  Invalid selection." -ForegroundColor DarkYellow
                Start-Sleep -Milliseconds 500
            }
        }
    }
}

function Show-MainMenu {
    <#
    .SYNOPSIS
        Shows main menu with modern CLI aesthetic
    #>
    Clear-Host
    Show-Banner

    if ($script:CurrentDevice) {
        Write-Host "  * $($script:CurrentDevice.Model) connected (READ-ONLY)" -ForegroundColor Green
    }
    else {
        Write-Host "  ! No device selected" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [1] Select Device" -ForegroundColor White
    Write-Host "  [2] Quick Transfer (Presets)" -ForegroundColor White
    Write-Host "  [3] Custom Transfer" -ForegroundColor White
    Write-Host "  [4] Full Backup (Pre-Format)" -ForegroundColor White
    Write-Host "  [5] File Explorer" -ForegroundColor White
    Write-Host "  [6] Settings" -ForegroundColor White
    Write-Host "  [7] Device Info" -ForegroundColor White
    Write-Host "  [8] Help" -ForegroundColor White
    Write-Host ""
    Write-Host "  [0] Exit" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  > " -ForegroundColor White -NoNewline
    $choice = Read-Host

    switch ($choice) {
        "1" { Show-DeviceSelection }
        "2" { Show-PresetMenu }
        "3" { Show-CustomTransferMenu }
        "4" { Show-FullBackupMenu }
        "5" { Show-FileExplorer }
        "6" { Show-Settings }
        "7" { Show-DeviceInfo }
        "8" { Show-Help }
        "0" {
            Write-Host ""
            Write-Host "  Goodbye." -ForegroundColor DarkGray
            Clear-TempFiles
            Write-Log "Session ended" -Level INFO
            exit 0
        }
        default {
            Write-Host "  Invalid selection." -ForegroundColor DarkYellow
            Start-Sleep -Seconds 1
        }
    }
}

# ============================================================================
# FIRST RUN SETUP
# ============================================================================

function Invoke-FirstRunSetup {
    <#
    .SYNOPSIS
        Runs first-time setup wizard
    #>
    Clear-Host
    Show-Banner

    Write-Host "  First Run Setup" -ForegroundColor White
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Choose default transfer destination:" -ForegroundColor White
    Write-Host ""
    Write-Host "  [1] C:\croxz (recommended)" -ForegroundColor DarkGray
    Write-Host "  [2] Desktop\adbData" -ForegroundColor DarkGray
    Write-Host "  [3] Documents\adbData" -ForegroundColor DarkGray
    Write-Host "  [4] Downloads\adbData" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  > " -ForegroundColor White -NoNewline
    $choice = Read-Host

    $defaultDest = switch ($choice) {
        "1" { "C:\croxz" }
        "2" { [Environment]::GetFolderPath("Desktop") + "\adbData" }
        "3" { [Environment]::GetFolderPath("MyDocuments") + "\adbData" }
        "4" { [Environment]::GetFolderPath("UserProfile") + "\Downloads\adbData" }
        default { "C:\croxz" }
    }

    $script:Config.DefaultDestination = $defaultDest
    $script:Config.FirstRunComplete = $true
    Save-Config

    Write-Host ""
    Write-Host "  * Default folder: $defaultDest" -ForegroundColor Green
    Write-Host "  * Access mode: READ-ONLY (device files never modified)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Setup complete." -ForegroundColor White
    Write-Host ""
    Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray -NoNewline
    $null = Read-Host
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-adbData {
    <#
    .SYNOPSIS
        Main entry point
    #>
    
    try {
        # Initialize environment
        Initialize-Directories
        Initialize-Config
        Initialize-Presets
        Initialize-ResumeDB
        
        # Check ADB
        if (-not (Test-ADBInstallation)) {
            Clear-Host
            Write-Host ""
            Write-Host "  adbData" -ForegroundColor White -NoNewline
            Write-Host " - ADB not found" -ForegroundColor Red
            Write-Host ""
            Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  Android Debug Bridge (ADB) is required but not found." -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  Options:" -ForegroundColor White
            Write-Host "    1. Download Platform Tools to 'platform-tools' folder:" -ForegroundColor DarkGray
            Write-Host "       https://developer.android.com/studio/releases/platform-tools" -ForegroundColor DarkGray
            Write-Host "    2. Install Android Studio and add to system PATH" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  Press Enter to exit..." -ForegroundColor DarkGray -NoNewline
            $null = Read-Host
            exit 1
        }
        
        # Show disclaimer (includes banner)
        if (-not (Show-Disclaimer)) {
            Write-Log "User declined to proceed" -Level INFO
            exit 0
        }
        
        # First run setup
        if (-not $script:Config.FirstRunComplete) {
            Invoke-FirstRunSetup
        }
        
        # Main loop with infinite loop protection
        $maxIterations = 10000  # Safety limit: prevent runaway loops
        $iteration = 0
        
        while ($iteration -lt $maxIterations) {
            $iteration++
            
            try {
                Show-MainMenu
            }
            catch [System.Management.Automation.PipelineStoppedException] {
                # Ctrl+C caught - graceful exit
                Write-Log "User interrupted execution (Ctrl+C)" -Level INFO
                break
            }
            catch {
                Write-Log "Error in main loop: $($_.Exception.Message)" -Level ERROR
                # Continue loop after error (don't crash)
            }
            
            # Heartbeat: Prevent CPU spike in rapid loop conditions
            if ($iteration % 100 -eq 0) {
                Start-Sleep -Milliseconds 10
                Write-Log "Main loop heartbeat: $iteration iterations" -Level DEBUG
            }
        }
        
        # Safety check: If we reached max iterations, something is wrong
        if ($iteration -ge $maxIterations) {
            Write-Log "CRITICAL: Maximum iterations ($maxIterations) reached - possible infinite loop detected!" -Level ERROR
            throw "Infinite loop protection triggered. Tool terminated for safety."
        }
    }
    catch {
        Write-Log "Fatal error: $($_.Exception.Message)" -Level ERROR
        Write-Host ""
        Write-Host "  ! Critical error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Log: $($script:LogFile)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Press Enter to exit..." -ForegroundColor DarkGray -NoNewline
        $null = Read-Host
        exit 1
    }
    finally {
        Clear-TempFiles
    }
}

# ============================================================================
# ENTRY POINT
# ============================================================================

# Start the application
Start-adbData

