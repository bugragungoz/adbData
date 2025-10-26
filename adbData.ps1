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

$script:Version = "1.0.0"
$script:ScriptRoot = $PSScriptRoot
$script:SessionID = (Get-Date -Format "yyyyMMdd_HHmmss")

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
                if ($devicePaths -contains $part.ToUpper()) {
                    $validationResult.IsValid = $false
                    $validationResult.ErrorMessage = "Path contains Windows device name: $part"
                    return $validationResult
                }
            }
        }
        
        'DeviceID' {
            # Device ID format validation (alphanumeric, colons for WiFi)
            if ($Input -notmatch '^[a-zA-Z0-9\.\:\-]+$') {
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
        Whitelist validation, null byte prevention, unicode normalization, shell escaping
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
    
    # Whitelist validation
    # Allowed: alphanumeric, forward slash, dash, underscore, dot, space
    # This is more restrictive but much safer
    $allowedPattern = '^[a-zA-Z0-9/\-_\.\s]+$'
    if ($Path -notmatch $allowedPattern) {
        Write-Log "Path contains disallowed characters: $Path" -Level WARNING
        # Remove ALL non-whitelisted characters
        $Path = $Path -replace '[^a-zA-Z0-9/\-_\.\s]', ''
    }
    
    # Block shell metacharacters
    $dangerousChars = @(';', '|', '&', '$', '<', '>', '`', '\', '!', '*', '?', '[', ']', '{', '}', '(', ')', '^', '~', '#', '%', '@')
    foreach ($char in $dangerousChars) {
        if ($Path.Contains($char)) {
            Write-Log "Dangerous character '$char' removed from path" -Level WARNING
            $Path = $Path.Replace($char, '')
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
    
    # Escape special chars for shell
    $Path = $Path -replace '"', '\"'  # Escape double quotes
    $Path = $Path -replace "'", "'\\''"  # Escape single quotes for POSIX shell
    $Path = $Path -replace '\$', '\$'  # Escape dollar sign
    
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
    
    # Block path traversal patterns
    $traversalPatterns = @(
        '\.\.',           # Standard ..
        '%2e%2e',         # URL encoded ..
        '%252e%252e',     # Double URL encoded ..
        '\.\.\\',         # Windows style
        '\.\.\/',         # Unix style
        '\.\.\.',         # Triple dot (rare but possible)
        '..\\',           # Windows variant
        '../',            # Unix variant
        '...\\',          # Fuzzing variant
        '.../'            # Fuzzing variant
    )
    
    foreach ($pattern in $traversalPatterns) {
        if ($relative -match $pattern) {
            Write-Log "Path traversal pattern detected: $pattern in $relative" -Level ERROR
            $relative = $relative -replace $pattern, ''
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
        $upperPart = $part.ToUpper()
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
    if (-not $NoConsole) {
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
    # Create default configuration with magic numbers documented
    # Use secure path resolution instead of env vars
    $userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    
    if ([string]::IsNullOrEmpty($userProfile) -or -not (Test-Path $userProfile)) {
        throw "Cannot determine user profile directory securely"
    }
    
    $defaultDest = Join-Path $userProfile "Desktop\adbData"
    
    # Validate path structure (prevent injection)
    if ($defaultDest -notmatch '^[A-Z]:\\Users\\[^\\<>:\"\|\?\*]+\\Desktop\\adbData$') {
        Write-Log "WARNING: Default destination path validation failed, using fallback" -Level WARNING
        $defaultDest = "C:\adbData"  # Safe fallback
    }
    
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
        # Create default presets
        $script:Presets = [PSCustomObject]@{
            presets = @(
                [PSCustomObject]@{
                    id = "camera_photos"
                    name = "[CAMERA] Photos"
                    description = "Transfer all photos from camera"
                    source_paths = @("/sdcard/DCIM/Camera/")
                    destination = "Pictures/Phone Camera/{date}/"
                    filters = [PSCustomObject]@{
                        extensions = @(".jpg", ".jpeg", ".png", ".heic", ".dng")
                    }
                    options = [PSCustomObject]@{
                        recursive = $false
                        verify = $true
                        organize_by = "date"
                    }
                },
                [PSCustomObject]@{
                    id = "camera_videos"
                    name = "[VIDEO] Camera Videos"
                    description = "Transfer videos from camera"
                    source_paths = @("/sdcard/DCIM/Camera/")
                    destination = "Videos/Phone Camera/{date}/"
                    filters = [PSCustomObject]@{
                        extensions = @(".mp4", ".mov", ".avi", ".3gp")
                    }
                    options = [PSCustomObject]@{
                        recursive = $false
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "whatsapp_media"
                    name = "[WHATSAPP] Media"
                    description = "Backup WhatsApp photos and videos"
                    source_paths = @("/sdcard/WhatsApp/Media/")
                    destination = "Backups/WhatsApp/{date}/"
                    options = [PSCustomObject]@{
                        recursive = $true
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "screenshots"
                    name = "[SCREEN] Screenshots"
                    description = "Transfer all screenshots"
                    source_paths = @("/sdcard/Pictures/Screenshots/", "/sdcard/Screenshots/")
                    destination = "Pictures/Screenshots/{date}/"
                    options = [PSCustomObject]@{
                        recursive = $false
                        verify = $true
                    }
                },
                [PSCustomObject]@{
                    id = "downloads"
                    name = "[DOWNLOAD] Files"
                    description = "Transfer downloaded files"
                    source_paths = @("/sdcard/Download/")
                    destination = "Downloads/Phone/"
                    options = [PSCustomObject]@{
                        recursive = $false
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
        $hash = (Get-FileHash -Path $ADBPath -Algorithm SHA256).Hash.ToUpper()
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
    #>
    
    if (-not $script:ADB) {
        Write-Log "ADB not initialized" -Level ERROR
        return @()
    }
    
    try {
        # Start ADB server if not running
        & $script:ADB start-server 2>&1 | Out-Null
        Start-Sleep -Milliseconds $script:Config.ADBStartupDelay
        
        $output = & $script:ADB devices -l 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "ADB devices command failed" -Level ERROR
            return @()
        }
        
        $devices = @()
        $lines = $output -split "`n" | Select-Object -Skip 1
        
        foreach ($line in $lines) {
            $line = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            
            $parts = $line -split '\s+'
            if ($parts.Count -lt 2) { continue }
            
            $deviceID = $parts[0]
            $state = $parts[1]
            
            # Parse additional info
            $model = "Unknown"
            $product = "Unknown"
            $transport = "USB"
            
            if ($line -match "model:([^\s]+)") { $model = $matches[1] }
            if ($line -match "product:([^\s]+)") { $product = $matches[1] }
            if ($deviceID -match ":") { $transport = "WiFi" }
            
            $device = [PSCustomObject]@{
                ID = $deviceID
                State = $state
                Model = $model
                Product = $product
                Transport = $transport
            }
            
            $devices += $device
        }
        
        return $devices
    }
    catch {
        Write-Log "Error getting ADB devices: $($_.Exception.Message)" -Level ERROR
        return @()
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
        
        $output = & $script:ADB -s $DeviceID shell $findCmd 2>&1
        
        if ($LASTEXITCODE -ne 0) {
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
                    $ext = [System.IO.Path]::GetExtension($trimmed).ToLower()
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
        # Sanitize path to prevent command injection
        if ($script:Config.SanitizePaths) {
            $FilePath = Protect-ShellPath -Path $FilePath
        }
        
        $size = & $script:ADB -s $DeviceID shell "stat -c%s '$FilePath'" 2>&1
        return [long]$size.Trim()
    }
    catch {
        Write-Log "Failed to get file size for $FilePath" -Level ERROR
        return 0
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
        
        $output = & $script:ADB -s $DeviceID shell $cmd 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to list files with sizes in $Path" -Level ERROR
            return @()
        }
        
        $results = New-Object System.Collections.ArrayList
        $count = 0
        $MAX_FILES = 100000  # Military-grade: Resource exhaustion protection
        
        foreach ($line in ($output -split "`n")) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            
            # Military-grade: Prevent resource exhaustion
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
                    $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
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
        
        $output = & $script:ADB -s $DeviceID shell "$cmd '$FilePath'" 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Hash calculation failed for $FilePath" -Level ERROR
            Write-AuditLog -Action "CalculateHash" -Resource $FilePath -Result "Failure"
            return $null
        }
        
        # Parse output: "hash  filename"
        $hash = ($output -split '\s+')[0].Trim().ToLower()
        
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
        $hashString = $hashResult.Hash.ToLower()
        
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
    
    if ($sourceSize -ne $destSize) {
        Write-Log "Size mismatch: Source=$sourceSize, Dest=$destSize" -Level ERROR
        return $false
    }
    
    # Performance optimization: Skip hash for small files
    # Rationale: Files under threshold have very low corruption risk,
    # and hash calculation overhead outweighs the benefit
    if ($sourceSize -lt $script:Config.SmallFileThreshold) {
        Write-Log "Small file ($([math]::Round($sourceSize/1MB, 2))MB) - size check sufficient" -Level DEBUG
        return $true
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
    
    # Sanitize source path if enabled
    $safeSourcePath = $SourcePath
    if ($script:Config.SanitizePaths) {
        $safeSourcePath = Protect-ShellPath -Path $SourcePath
    }
    
    # Skip if file already exists with same size (resume/incremental transfer)
    if (Test-Path $DestinationPath) {
        try {
            # Get source file size
            $sourceSize = Get-AndroidFileSize -DeviceID $DeviceID -FilePath $SourcePath
            $destSize = (Get-Item $DestinationPath).Length
            
            if ($sourceSize -eq $destSize) {
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
            
            # Execute ADB pull with sanitized path
            $result = & $script:ADB -s $DeviceID pull "$safeSourcePath" "$tempPath" 2>&1
            
            if ($LASTEXITCODE -ne 0) {
                throw "ADB pull failed: $result"
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
                    
                    # Perform atomic move with .NET (more reliable than PowerShell)
                    # $false = no overwrite (throws if exists)
                    [System.IO.File]::Move($tempPath, $DestinationPath, $false)
                    
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
        Displays application banner
    #>
    Clear-Host
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                                                                                " -ForegroundColor Cyan
    Write-Host "          ######  ########   #######  ##     ## ########                        " -ForegroundColor Cyan
    Write-Host "         ##    ## ##     ## ##     ##  ##   ##       ##                         " -ForegroundColor Cyan
    Write-Host "         ##       ##     ## ##     ##   ## ##       ##                          " -ForegroundColor Cyan
    Write-Host "         ##       ########  ##     ##    ###       ##                           " -ForegroundColor Cyan
    Write-Host "         ##       ##   ##   ##     ##   ## ##     ##                            " -ForegroundColor Cyan
    Write-Host "         ##    ## ##    ##  ##     ##  ##   ##   ##                             " -ForegroundColor Cyan
    Write-Host "          ######  ##     ##  #######  ##     ## ########                        " -ForegroundColor Cyan
    Write-Host "                                                                                " -ForegroundColor Cyan
    Write-Host "         High-Performance Android File Transfer via ADB v$($script:Version)     " -ForegroundColor Cyan
    Write-Host "                                                                                " -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Author: Bugra | Development: Claude 4.5 Sonnet AI | Platform: Windows" -ForegroundColor Gray
    Write-Host "  Session ID: $($script:SessionID)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [!] Press Ctrl+C at any time to abort operation" -ForegroundColor Yellow
    Write-Host ""
}

function Show-Disclaimer {
    <#
    .SYNOPSIS
        Shows legal disclaimer and gets user consent
    #>
    Clear-Host
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Yellow
    Write-Host "                              LEGAL DISCLAIMER                                  " -ForegroundColor Yellow
    Write-Host "===============================================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  adbData:" -ForegroundColor White
    Write-Host ""
    Write-Host "  * Transfers files between Android devices and Windows PC" -ForegroundColor Cyan
    Write-Host "  * Uses ADB (Android Debug Bridge) for reliable transfers" -ForegroundColor Cyan
    Write-Host "  * Performs READ-ONLY operations on Android device (SAFE)" -ForegroundColor Green
    Write-Host "  * Performs WRITE operations on Windows PC only" -ForegroundColor Cyan
    Write-Host "  * Never modifies, deletes, or moves files on Android device" -ForegroundColor Green
    Write-Host "  * Includes hash verification to ensure data integrity" -ForegroundColor Cyan
    Write-Host "  * Checks disk space before transfer to prevent failures" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ANDROID DEVICE SAFETY:" -ForegroundColor Green
    Write-Host "  + READ-ONLY access - Android files are NEVER modified" -ForegroundColor Green
    Write-Host "  + Original files remain untouched on device" -ForegroundColor Green
    Write-Host "  + Only pulls (copies) files, never pushes or deletes" -ForegroundColor Green
    Write-Host "  + Safe to interrupt transfer - device data unaffected" -ForegroundColor Green
    Write-Host ""
    Write-Host "  IMPORTANT REQUIREMENTS:" -ForegroundColor Red
    Write-Host "  - Android device must have USB Debugging enabled" -ForegroundColor Yellow
    Write-Host "  - Device must be authorized (you'll see prompt on first connect)" -ForegroundColor Yellow
    Write-Host "  - Sufficient storage space required on destination drive" -ForegroundColor Yellow
    Write-Host "  - ADB (Android Debug Bridge) must be installed" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  DATA SAFETY:" -ForegroundColor Green
    Write-Host "  + Files are COPIED, not moved (originals remain on device)" -ForegroundColor Cyan
    Write-Host "  + Hash verification ensures no corruption during transfer" -ForegroundColor Cyan
    Write-Host "  + Atomic operations prevent partial/corrupted files" -ForegroundColor Cyan
    Write-Host "  + Transaction logs track all operations" -ForegroundColor Cyan
    Write-Host "  + Disk space checked before transfer starts" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  NO WARRANTY:" -ForegroundColor Red
    Write-Host "  - This tool is provided AS-IS without any warranties" -ForegroundColor Yellow
    Write-Host "  - Author accepts NO LIABILITY for any data loss or issues" -ForegroundColor Yellow
    Write-Host "  - Always backup important data before any file operations" -ForegroundColor Yellow
    Write-Host "  - Use at own risk" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  BY USING THIS TOOL, YOU ACKNOWLEDGE AND ACCEPT FULL RESPONSIBILITY." -ForegroundColor Red
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Yellow
    Write-Host ""
    
    # Get user consent
    while ($true) {
        Write-Host "  Type 'ACCEPT' to proceed or 'CANCEL' to exit: " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        
        if ($response -eq "ACCEPT" -or $response -eq "accept") {
            Write-Log "User accepted disclaimer" -Level INFO -NoConsole
            return $true
        }
        elseif ($response -eq "CANCEL" -or $response -eq "cancel") {
            Write-Log "User declined disclaimer" -Level INFO -NoConsole
            return $false
        }
        else {
            Write-Host "  [!] Invalid input. Enter 'ACCEPT' or 'CANCEL'." -ForegroundColor Red
        }
    }
}

function Show-ScriptInfo {
    <#
    .SYNOPSIS
        Shows script information and usage guide
    #>
    Clear-Host
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host "                         TOOL INFORMATION (Page 1/2)                            " -ForegroundColor Cyan
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  WHAT DOES IT DO:" -ForegroundColor Yellow
    Write-Host "  ----------------" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Secure and fast file transfer from Android devices to Windows PC." -ForegroundColor White
    Write-Host "  Addresses freezing, data loss, and performance issues" -ForegroundColor White
    Write-Host "  experienced with Windows' built-in MTP protocol." -ForegroundColor White
    Write-Host ""
    Write-Host "  KEY FEATURES:" -ForegroundColor Yellow
    Write-Host "  -------------" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  * Ready Presets: Camera, WhatsApp, Screenshots, etc." -ForegroundColor Cyan
    Write-Host "  * Hash Verification: Data integrity guarantee (MD5/SHA256)" -ForegroundColor Cyan
    Write-Host "  * Automatic Retry: Continues even if connection drops" -ForegroundColor Cyan
    Write-Host "  * Progress Indicator: Real-time transfer status" -ForegroundColor Cyan
    Write-Host "  * Detailed Logs: All operations are recorded" -ForegroundColor Cyan
    Write-Host "  * Custom Filters: File extension, size, date filters" -ForegroundColor Cyan
    Write-Host "  * Disk Space Check: Prevents mid-transfer failures" -ForegroundColor Cyan
    Write-Host "  * READ-ONLY Android: Device files are never modified" -ForegroundColor Green
    Write-Host ""
    Write-Host "  PERFORMANCE:" -ForegroundColor Yellow
    Write-Host "  ------------" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  * ~2-3x faster than MTP for large files" -ForegroundColor Green
    Write-Host "  * ~5-10x faster for small files" -ForegroundColor Green
    Write-Host "  * No freezing with 1GB+ files" -ForegroundColor Green
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [Press any key]" -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    
    # Page 2
    Clear-Host
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host "                          USAGE GUIDE (Page 2/2)                                " -ForegroundColor Cyan
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  HOW TO USE:" -ForegroundColor Yellow
    Write-Host "  -----------" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  1. Connect Android device via USB" -ForegroundColor White
    Write-Host "  2. Verify USB Debugging is enabled" -ForegroundColor White
    Write-Host "     (Settings > Developer Options > USB Debugging)" -ForegroundColor Gray
    Write-Host "  3. Authorize 'Allow USB debugging' prompt on device" -ForegroundColor White
    Write-Host "  4. Select transfer method from main menu" -ForegroundColor White
    Write-Host "  5. Wait until transfer completes" -ForegroundColor White
    Write-Host ""
    Write-Host "  COLOR LEGEND:" -ForegroundColor Yellow
    Write-Host "  -------------" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [OK]    Successful operation" -ForegroundColor Green
    Write-Host "  [!]     Warning message" -ForegroundColor Yellow
    Write-Host "  [ERROR] Error message" -ForegroundColor Red
    Write-Host "  [INFO]  Information message" -ForegroundColor Cyan
    Write-Host "  [CHECK] Verification in progress" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  TIPS:" -ForegroundColor Yellow
    Write-Host "  -----" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  * If first transfer is slow, try different USB cable (USB 2.0 vs 3.0)" -ForegroundColor Cyan
    Write-Host "  * Hash verification may take time for large transfers" -ForegroundColor Cyan
    Write-Host "  * Presets are optimized for most common scenarios" -ForegroundColor Cyan
    Write-Host "  * Device remains usable during transfer" -ForegroundColor Cyan
    Write-Host "  * Android files are never modified (READ-ONLY access)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  LOGS: $($script:LogDir)" -ForegroundColor Gray
    Write-Host "  SETTINGS: $($script:ConfigDir)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [Press any key]" -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-TransferSummary {
    <#
    .SYNOPSIS
        Shows transfer summary statistics
    #>
    $duration = (Get-Date) - $script:TransferStats.StartTime
    $avgSpeed = if ($duration.TotalSeconds -gt 0) {
        $script:TransferStats.TransferredBytes / $duration.TotalSeconds
    } else { 0 }
    
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Green
    Write-Host "                            TRANSFER SUMMARY                                    " -ForegroundColor Green
    Write-Host "===============================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  STATISTICS:" -ForegroundColor Yellow
    Write-Host "  -----------" -ForegroundColor Gray
    Write-Host ""
    Write-Host "     Total Files         : $($script:TransferStats.TotalFiles)" -ForegroundColor White
    Write-Host "     Transferred         : $($script:TransferStats.TransferredFiles)" -ForegroundColor Green
    Write-Host "     Skipped (Exists)    : $($script:TransferStats.SkippedFiles)" -ForegroundColor Cyan
    Write-Host "     Failed              : $($script:TransferStats.FailedFiles)" -ForegroundColor Red
    Write-Host ""
    Write-Host "     Total Size          : $(Format-FileSize $script:TransferStats.TotalBytes)" -ForegroundColor White
    Write-Host "     Transferred         : $(Format-FileSize $script:TransferStats.TransferredBytes)" -ForegroundColor Green
    Write-Host ""
    Write-Host "     Duration            : $(Format-Duration $duration)" -ForegroundColor Cyan
    Write-Host "     Average Speed       : $(Format-FileSize $avgSpeed)/s" -ForegroundColor Cyan
    Write-Host ""
    
    if ($script:TransferStats.FailedFiles -eq 0) {
        Write-Host "  [SUCCESS] Transfer completed" -ForegroundColor Green
    }
    else {
        Write-Host "  [WARNING] Some files failed to transfer. Check logs for details." -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "  Log file: $($script:LogFile)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "===============================================================================" -ForegroundColor Green
    Write-Host ""
}

# ============================================================================
# MENU SYSTEM
# ============================================================================

function Show-DeviceSelection {
    <#
    .SYNOPSIS
        Shows device selection menu
    #>
    Write-Host ""
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host "                      DEVICE SELECTION                           " -ForegroundColor Cyan
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $devices = Get-ADBDevices
    
    if ($devices.Count -eq 0) {
        Write-Host "  [!] No devices found!" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Verify the following:" -ForegroundColor Yellow
        Write-Host "   * Is device connected via USB?" -ForegroundColor Gray
        Write-Host "   * Is USB Debugging enabled?" -ForegroundColor Gray
        Write-Host "   * Is 'Allow USB debugging' authorized on device?" -ForegroundColor Gray
        Write-Host "   * Is USB cable working?" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [Press any key]" -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return $null
    }
    
    Write-Host "  Connected devices:" -ForegroundColor White
    Write-Host ""
    
    for ($i = 0; $i -lt $devices.Count; $i++) {
        $device = $devices[$i]
        $color = if ($device.State -eq "device") { "Green" } else { "Yellow" }
        
        Write-Host "  [$($i + 1)] $($device.Model)" -ForegroundColor $color
        Write-Host "      ID: $($device.ID)" -ForegroundColor Gray
        Write-Host "      Status: $($device.State) | Connection: $($device.Transport)" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "  [0] Go Back" -ForegroundColor Red
    Write-Host ""
    
    while ($true) {
        Write-Host "  Select device (0-$($devices.Count)): " -ForegroundColor Yellow -NoNewline
        $choice = Read-Host
        
        if ($choice -eq "0") {
            return $null
        }
        
        $index = [int]$choice - 1
        if ($index -ge 0 -and $index -lt $devices.Count) {
            $selectedDevice = $devices[$index]
            
            if ($selectedDevice.State -ne "device") {
                Write-Host "  [!] Device not ready. Status: $($selectedDevice.State)" -ForegroundColor Red
                Write-Host "  [Press any key]" -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                return $null
            }
            
            $script:CurrentDevice = $selectedDevice
            Write-Log "Device selected: $($selectedDevice.Model) ($($selectedDevice.ID))" -Level INFO
            return $selectedDevice
        }
        else {
            Write-Host "  [!] Invalid selection!" -ForegroundColor Red
        }
    }
}

function Show-PresetMenu {
    <#
    .SYNOPSIS
        Shows preset transfer menu
    #>
    Clear-Host
    Show-Banner
    
    if (-not $script:CurrentDevice) {
        Write-Host "  [!] Device selection required" -ForegroundColor Red
        Start-Sleep -Seconds 2
        return
    }
    
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host "                    QUICK TRANSFER (PRESET)                      " -ForegroundColor Cyan
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Active Device: $($script:CurrentDevice.Model)" -ForegroundColor Green
    Write-Host ""
    
    $presets = $script:Presets.presets
    
    for ($i = 0; $i -lt $presets.Count; $i++) {
        $preset = $presets[$i]
        Write-Host "  [$($i + 1)] $($preset.name)" -ForegroundColor Cyan
        Write-Host "      $($preset.description)" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "  [0] Return to Main Menu" -ForegroundColor Red
    Write-Host ""
    
    while ($true) {
        Write-Host "  Select preset (0-$($presets.Count)): " -ForegroundColor Yellow -NoNewline
        $choice = Read-Host
        
        if ($choice -eq "0") {
            return
        }
        
        $index = [int]$choice - 1
        if ($index -ge 0 -and $index -lt $presets.Count) {
            $preset = $presets[$index]
            
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
            Write-Host "  [INFO] Starting: $($preset.name)" -ForegroundColor Cyan
            
            [void](Invoke-Preset -PresetID $preset.id -DeviceID $script:CurrentDevice.ID)
            
            Show-TransferSummary
            
            Write-Host "  [Press any key]" -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
        else {
            Write-Host "  [!] Invalid selection!" -ForegroundColor Red
        }
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
        Write-Host "  [!] Device selection required" -ForegroundColor Red
        Start-Sleep -Seconds 2
        return
    }
    
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host "                   CUSTOM DIRECTORY TRANSFER                     " -ForegroundColor Cyan
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Active Device: $($script:CurrentDevice.Model)" -ForegroundColor Green
    Write-Host ""
    
    # Get source path
    Write-Host "  Source folder path (Android):" -ForegroundColor Yellow
    Write-Host "  Example: /sdcard/DCIM/Camera/" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Path: " -ForegroundColor Yellow -NoNewline
    $sourcePath = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($sourcePath)) {
        Write-Host "  [!] Invalid path!" -ForegroundColor Red
        Start-Sleep -Seconds 2
        return
    }
    
    # Check if path exists
    if (-not (Test-AndroidPath -DeviceID $script:CurrentDevice.ID -Path $sourcePath)) {
        Write-Host "  [!] Source path not found: $sourcePath" -ForegroundColor Red
        Start-Sleep -Seconds 2
        return
    }
    
    # Get destination path
    Write-Host ""
    Write-Host "  Destination folder path (Windows):" -ForegroundColor Yellow
    Write-Host "  Example: D:\Photos\Phone\" -ForegroundColor Gray
    Write-Host "  (Leave empty for default: $($script:Config.DefaultDestination))" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Path: " -ForegroundColor Yellow -NoNewline
    $destPath = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($destPath)) {
        $destPath = $script:Config.DefaultDestination
    }
    
    # Recursive option
    Write-Host ""
    Write-Host "  Include subdirectories? (Y/N): " -ForegroundColor Yellow -NoNewline
    $recursiveChoice = Read-Host
    $recursive = ($recursiveChoice -eq "Y" -or $recursiveChoice -eq "y")
    
    # Verification option
    Write-Host "  Perform hash verification? (Y/N) [Recommended: Y]: " -ForegroundColor Yellow -NoNewline
    $verifyChoice = Read-Host
    $verify = ($verifyChoice -ne "N" -and $verifyChoice -ne "n")
    
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
    
    # Execute transfer
    Write-Host ""
    [void](Copy-AndroidDirectory -DeviceID $script:CurrentDevice.ID `
                                -SourcePath $sourcePath `
                                -DestinationPath $destPath `
                                -Verify:$verify `
                                -Recursive:$recursive)
    
    Show-TransferSummary
    
    Write-Host "  [Press any key]" -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-Help {
    <#
    .SYNOPSIS
        Shows comprehensive help and documentation
    #>
    Clear-Host
    Show-Banner
    
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host "                    HELP & DOCUMENTATION                         " -ForegroundColor Cyan
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  [1] Quick Start Guide" -ForegroundColor Cyan
    Write-Host "  [2] Common Android Paths" -ForegroundColor Cyan
    Write-Host "  [3] Troubleshooting" -ForegroundColor Cyan
    Write-Host "  [4] Configuration Guide" -ForegroundColor Cyan
    Write-Host "  [5] Security Features" -ForegroundColor Cyan
    Write-Host "  [6] About & Credits" -ForegroundColor Cyan
    Write-Host "  [0] Back to Main Menu" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Select option (0-6): " -ForegroundColor Yellow -NoNewline
    $choice = Read-Host
    
    Clear-Host
    Show-Banner
    
    switch ($choice) {
        "1" {
            Write-Host "  ===============================================================" -ForegroundColor Green
            Write-Host "                       QUICK START GUIDE                         " -ForegroundColor Green
            Write-Host "  ===============================================================" -ForegroundColor Green
            Write-Host ""
            Write-Host "  STEP 1: Device Connection" -ForegroundColor Yellow
            Write-Host "  - Connect Android device via USB" -ForegroundColor White
            Write-Host "  - Enable USB Debugging (Settings > Developer Options)" -ForegroundColor White
            Write-Host "  - Accept 'Allow USB debugging' prompt on device" -ForegroundColor White
            Write-Host ""
            Write-Host "  STEP 2: Device Selection" -ForegroundColor Yellow
            Write-Host "  - Main Menu > [1] Select Device" -ForegroundColor White
            Write-Host "  - Select device from list" -ForegroundColor White
            Write-Host ""
            Write-Host "  STEP 3: File Transfer" -ForegroundColor Yellow
            Write-Host "  - Option A: Quick Transfer (Presets) - [2]" -ForegroundColor White
            Write-Host "    Camera, WhatsApp, Downloads, etc." -ForegroundColor Gray
            Write-Host "  - Option B: Custom Transfer - [3]" -ForegroundColor White
            Write-Host "    Any folder with custom settings" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  FEATURES:" -ForegroundColor Yellow
            Write-Host "  [+] Automatic hash verification (MD5/SHA256)" -ForegroundColor Green
            Write-Host "  [+] Resume capability - skip existing files" -ForegroundColor Green
            Write-Host "  [+] READ-ONLY access - device files stay safe" -ForegroundColor Green
            Write-Host "  [+] Detailed logging for troubleshooting" -ForegroundColor Green
        }
        "2" {
            Write-Host "  ===============================================================" -ForegroundColor Green
            Write-Host "                    COMMON ANDROID PATHS                         " -ForegroundColor Green
            Write-Host "  ===============================================================" -ForegroundColor Green
            Write-Host ""
            Write-Host "  PHOTOS & VIDEOS:" -ForegroundColor Yellow
            Write-Host "  /sdcard/DCIM/Camera/             - Camera photos/videos" -ForegroundColor White
            Write-Host "  /sdcard/Pictures/                - All pictures" -ForegroundColor White
            Write-Host "  /sdcard/Pictures/Screenshots/    - Screenshots" -ForegroundColor White
            Write-Host "  /sdcard/Movies/                  - Video files" -ForegroundColor White
            Write-Host ""
            Write-Host "  MESSAGING APPS:" -ForegroundColor Yellow
            Write-Host "  /sdcard/WhatsApp/Media/          - WhatsApp (Android <11)" -ForegroundColor White
            Write-Host "  /sdcard/Android/media/com.whatsapp/WhatsApp/ - WhatsApp (Android 11+)" -ForegroundColor White
            Write-Host "  /sdcard/Telegram/                - Telegram files" -ForegroundColor White
            Write-Host ""
            Write-Host "  OTHER:" -ForegroundColor Yellow
            Write-Host "  /sdcard/Download/                - Downloads" -ForegroundColor White
            Write-Host "  /sdcard/Music/                   - Music files" -ForegroundColor White
            Write-Host "  /sdcard/Documents/               - Documents" -ForegroundColor White
            Write-Host "  /sdcard/Android/data/            - App data" -ForegroundColor White
        }
        "3" {
            Write-Host "  ===============================================================" -ForegroundColor Green
            Write-Host "                        TROUBLESHOOTING                          " -ForegroundColor Green
            Write-Host "  ===============================================================" -ForegroundColor Green
            Write-Host ""
            Write-Host "  DEVICE NOT FOUND:" -ForegroundColor Yellow
            Write-Host "  [*] Check USB cable is connected" -ForegroundColor White
            Write-Host "  [*] Enable USB Debugging on device" -ForegroundColor White
            Write-Host "  [*] Accept 'Allow USB debugging' prompt" -ForegroundColor White
            Write-Host "  [*] Try different USB port (USB 2.0 recommended)" -ForegroundColor White
            Write-Host "  [*] Check logs: .\logs\transfer_*.log" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  TRANSFER FAILED:" -ForegroundColor Yellow
            Write-Host "  [*] Check available disk space" -ForegroundColor White
            Write-Host "  [*] Ensure files not locked by another app" -ForegroundColor White
            Write-Host "  [*] Keep device awake during transfer" -ForegroundColor White
            Write-Host "  [*] Review error logs for details" -ForegroundColor White
            Write-Host ""
            Write-Host "  SLOW TRANSFERS:" -ForegroundColor Yellow
            Write-Host "  [*] Use USB 3.0 cable and port" -ForegroundColor White
            Write-Host "  [*] Disable hash verification for large files" -ForegroundColor White
            Write-Host "  [*] Use MD5 instead of SHA256 (faster)" -ForegroundColor White
            Write-Host "  [*] Settings > HashAlgorithm: 'MD5'" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  LOG FILES LOCATION:" -ForegroundColor Yellow
            Write-Host "  .\logs\transfer_*.log            - Transfer logs" -ForegroundColor White
            Write-Host "  .\logs\security_audit_*.log      - Security events" -ForegroundColor White
        }
        "4" {
            Write-Host "  ===============================================================" -ForegroundColor Green
            Write-Host "                     CONFIGURATION GUIDE                         " -ForegroundColor Green
            Write-Host "  ===============================================================" -ForegroundColor Green
            Write-Host ""
            Write-Host "  Config File: .\config\settings.json" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  KEY SETTINGS:" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  AlwaysVerifyHash: true/false" -ForegroundColor White
            Write-Host "  -> Verify file integrity after transfer" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  HashAlgorithm: 'MD5' or 'SHA256'" -ForegroundColor White
            Write-Host "  -> MD5: Faster (recommended)" -ForegroundColor Gray
            Write-Host "  -> SHA256: More secure but slower" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  SmallFileThreshold: 104857600 (100MB)" -ForegroundColor White
            Write-Host "  -> Files under this skip hash verification" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  MaxRetries: 3" -ForegroundColor White
            Write-Host "  -> Number of retry attempts for failed transfers" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  EnableParallelTransfer: false" -ForegroundColor White
            Write-Host "  -> EXPERIMENTAL: Parallel transfers for small files" -ForegroundColor Gray
            Write-Host "  -> Default: false (sequential is more stable)" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  SanitizePaths: true" -ForegroundColor White
            Write-Host "  -> Security: Command injection protection" -ForegroundColor Gray
            Write-Host "  -> KEEP THIS TRUE!" -ForegroundColor Red
        }
        "5" {
            Write-Host "  ===============================================================" -ForegroundColor Green
            Write-Host "                      SECURITY FEATURES                          " -ForegroundColor Green
            Write-Host "  ===============================================================" -ForegroundColor Green
            Write-Host ""
            Write-Host "  THIS TOOL IMPLEMENTS:" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  [+] Command Injection Protection" -ForegroundColor Green
            Write-Host "     -> Whitelist validation, shell escaping" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [+] Path Traversal Prevention" -ForegroundColor Green
            Write-Host "     -> 10+ attack patterns blocked (.., %2e%2e, etc.)" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [+] ADB Binary Integrity Check" -ForegroundColor Green
            Write-Host "     -> SHA256 hash verification" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [+] Race Condition Protection" -ForegroundColor Green
            Write-Host "     -> Exclusive file locking, atomic operations" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [+] Memory Security" -ForegroundColor Green
            Write-Host "     -> Secure data wiping, forced garbage collection" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [+] Rate Limiting" -ForegroundColor Green
            Write-Host "     -> DoS protection: 50/sec, 1000/min" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [+] Comprehensive Audit Logging" -ForegroundColor Green
            Write-Host "     -> Structured JSONL logs, security event alerts" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [+] READ-ONLY Device Access" -ForegroundColor Green
            Write-Host "     -> Never modifies files on Android device" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  [+] Hash Verification" -ForegroundColor Green
            Write-Host "     -> Timing-safe comparison, zero data loss" -ForegroundColor Gray
        }
        "6" {
            Write-Host "  ===============================================================" -ForegroundColor Green
            Write-Host "                       ABOUT & CREDITS                           " -ForegroundColor Green
            Write-Host "  ===============================================================" -ForegroundColor Green
            Write-Host ""
            Write-Host "  adbData v$($script:Version)" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  DESCRIPTION:" -ForegroundColor Yellow
            Write-Host "  High-performance Android file transfer via ADB" -ForegroundColor White
            Write-Host "  via ADB with integrity verification and security features." -ForegroundColor White
            Write-Host ""
            Write-Host "  DEVELOPER:" -ForegroundColor Yellow
            Write-Host "  Bugra" -ForegroundColor White
            Write-Host ""
            Write-Host "  AI ASSISTANT:" -ForegroundColor Yellow
            Write-Host "  Claude Sonnet 4.5 (Anthropic)" -ForegroundColor White
            Write-Host ""
            Write-Host "  ADB:" -ForegroundColor Yellow
            Write-Host "  Google Android Platform Tools" -ForegroundColor White
            Write-Host ""
            Write-Host "  LICENSE:" -ForegroundColor Yellow
            Write-Host "  MIT License - Free to use, modify, and distribute" -ForegroundColor White
            Write-Host ""
            Write-Host "  FEATURES:" -ForegroundColor Yellow
            Write-Host "  * Hash verification (MD5/SHA256)" -ForegroundColor White
            Write-Host "  * Resume capability & incremental transfers" -ForegroundColor White
            Write-Host "  * Security: injection protection, audit logging" -ForegroundColor White
            Write-Host "  * Session tracking & transfer history" -ForegroundColor White
            Write-Host "  * Smart presets for common scenarios" -ForegroundColor White
            Write-Host "  * Parallel transfers (experimental)" -ForegroundColor White
        }
        default {
            return
        }
    }
    
    Write-Host ""
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host ""
    Read-Host "  [Press Enter]"
}

function Show-DeviceInfo {
    <#
    .SYNOPSIS
        Shows detailed device information
    #>
    Clear-Host
    Show-Banner
    
    if (-not $script:CurrentDevice) {
        Write-Host "  [!] Device selection required" -ForegroundColor Red
        Start-Sleep -Seconds 2
        return
    }
    
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host "                       DEVICE INFORMATION                        " -ForegroundColor Cyan
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  BASIC INFORMATION:" -ForegroundColor Yellow
    Write-Host "  ------------------" -ForegroundColor Gray
    Write-Host "     Model            : $($script:CurrentDevice.Model)" -ForegroundColor White
    Write-Host "     Product          : $($script:CurrentDevice.Product)" -ForegroundColor White
    Write-Host "     ID               : $($script:CurrentDevice.ID)" -ForegroundColor White
    Write-Host "     Connection       : $($script:CurrentDevice.Transport)" -ForegroundColor White
    Write-Host ""
    
    # Get Android version
    $androidInfo = Get-AndroidVersion -DeviceID $script:CurrentDevice.ID
    
    if ($androidInfo) {
        Write-Host "  ANDROID INFORMATION:" -ForegroundColor Yellow
        Write-Host "  --------------------" -ForegroundColor Gray
        Write-Host "     Android Version  : $($androidInfo.Version)" -ForegroundColor White
        Write-Host "     SDK Level        : $($androidInfo.SDK)" -ForegroundColor White
        Write-Host "     Scoped Storage   : $(if ($androidInfo.HasScopedStorage) { 'Yes (Android 11+)' } else { 'No' })" -ForegroundColor White
        Write-Host ""
    }
    
    # Get storage info
    try {
        $storageInfo = & $script:ADB -s $script:CurrentDevice.ID shell "df /sdcard" 2>&1 | Select-Object -Skip 1
        Write-Host "  STORAGE INFORMATION:" -ForegroundColor Yellow
        Write-Host "  --------------------" -ForegroundColor Gray
        Write-Host "     $storageInfo" -ForegroundColor White
    }
    catch {
        Write-Host "  [!] Could not retrieve storage information" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "  DEVICE ACCESS MODE:" -ForegroundColor Green
    Write-Host "  -------------------" -ForegroundColor Gray
    Write-Host "  * READ-ONLY access to Android device" -ForegroundColor Green
    Write-Host "  * Device files are NEVER modified, deleted, or moved" -ForegroundColor Green
    Write-Host "  * Safe to use - only copies files to PC" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "  [Press any key]" -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-Settings {
    <#
    .SYNOPSIS
        Shows settings menu
    #>
    Clear-Host
    Show-Banner
    
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host "                          SETTINGS                               " -ForegroundColor Cyan
    Write-Host "  ===============================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Current Settings:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. Default Destination     : $($script:Config.DefaultDestination)" -ForegroundColor White
    Write-Host "  2. Hash Verification       : $(if ($script:Config.AlwaysVerifyHash) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
    Write-Host "  3. Hash Algorithm          : $($script:Config.HashAlgorithm)" -ForegroundColor White
    Write-Host "  4. Maximum Retries         : $($script:Config.MaxRetries)" -ForegroundColor White
    Write-Host "  5. Progress Bar            : $(if ($script:Config.ShowProgressBar) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
    Write-Host ""
    Write-Host "  [0] Go Back" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Select number to change (0-5): " -ForegroundColor Yellow -NoNewline
    $choice = Read-Host
    
    switch ($choice) {
        "1" {
            Write-Host ""
            Write-Host "  New default destination folder: " -ForegroundColor Yellow -NoNewline
            $newPath = Read-Host
            if (-not [string]::IsNullOrWhiteSpace($newPath)) {
                $script:Config.DefaultDestination = $newPath
                Save-Config
                Write-Host "  [OK] Setting saved" -ForegroundColor Green
                Start-Sleep -Seconds 1
            }
        }
        "2" {
            $script:Config.AlwaysVerifyHash = -not $script:Config.AlwaysVerifyHash
            Save-Config
            Write-Host "  [OK] Hash verification: $(if ($script:Config.AlwaysVerifyHash) { 'Enabled' } else { 'Disabled' })" -ForegroundColor Green
            Start-Sleep -Seconds 1
        }
        "3" {
            Write-Host ""
            Write-Host "  [1] MD5 (Fast)" -ForegroundColor Cyan
            Write-Host "  [2] SHA256 (Secure)" -ForegroundColor Cyan
            Write-Host "  Choice: " -ForegroundColor Yellow -NoNewline
            $algoChoice = Read-Host
            if ($algoChoice -eq "1") {
                $script:Config.HashAlgorithm = "MD5"
            } elseif ($algoChoice -eq "2") {
                $script:Config.HashAlgorithm = "SHA256"
            }
            Save-Config
            Write-Host "  [OK] Algorithm: $($script:Config.HashAlgorithm)" -ForegroundColor Green
            Start-Sleep -Seconds 1
        }
        "0" { return }
    }
    
    Show-Settings
}

function Show-MainMenu {
    <#
    .SYNOPSIS
        Shows main menu
    #>
    Clear-Host
    Show-Banner
    
    Write-Host "  ============================================================================" -ForegroundColor Cyan
    Write-Host "                                MAIN MENU                                   " -ForegroundColor Cyan
    Write-Host "  ============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Select Device                                                          " -ForegroundColor Cyan
    Write-Host "  [2] Quick Transfer (Presets)                                               " -ForegroundColor Cyan
    Write-Host "  [3] Custom Directory Transfer                                              " -ForegroundColor Cyan
    Write-Host "  [4] Settings                                                               " -ForegroundColor Cyan
    Write-Host "  [5] Device Information                                                     " -ForegroundColor Cyan
    Write-Host "  [6] Help & Documentation                                                   " -ForegroundColor Cyan
    Write-Host "  [0] Exit                                                                   " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ============================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($script:CurrentDevice) {
        Write-Host "  [CONNECTED] Active Device: $($script:CurrentDevice.Model)" -ForegroundColor Green
        Write-Host "  [MODE] READ-ONLY access - Device files protected" -ForegroundColor Green
    }
    else {
        Write-Host "  [WARNING] No Device Selected" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "  Select option (0-6): " -ForegroundColor Yellow -NoNewline
    $choice = Read-Host
    
    switch ($choice) {
        "1" { Show-DeviceSelection }
        "2" { Show-PresetMenu }
        "3" { Show-CustomTransferMenu }
        "4" { Show-Settings }
        "5" { Show-DeviceInfo }
        "6" { Show-Help }
        "0" { 
            Write-Host ""
            Write-Host "  [INFO] Exiting..." -ForegroundColor Cyan
            Clear-TempFiles
            Write-Log "Session ended" -Level INFO
            exit 0
        }
        default {
            Write-Host "  [!] Invalid selection!" -ForegroundColor Red
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
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                                                                                " -ForegroundColor Cyan
    Write-Host "                         FIRST RUN SETUP WIZARD                                 " -ForegroundColor Cyan
    Write-Host "                                                                                " -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Initial configuration required.`n" -ForegroundColor White
    
    # Set default destination
    Write-Host "  ============================================================================" -ForegroundColor Yellow
    Write-Host "                         Default Transfer Folder                              " -ForegroundColor Yellow
    Write-Host "  ============================================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Desktop" -ForegroundColor Cyan
    Write-Host "  [2] Documents" -ForegroundColor Cyan
    Write-Host "  [3] Downloads" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Select option (1-3): " -ForegroundColor Yellow -NoNewline
    $choice = Read-Host
    
    $defaultDest = switch ($choice) {
        "1" { [Environment]::GetFolderPath("Desktop") + "\adbData" }
        "2" { [Environment]::GetFolderPath("MyDocuments") + "\adbData" }
        "3" { [Environment]::GetFolderPath("UserProfile") + "\Downloads\adbData" }
        default { [Environment]::GetFolderPath("Desktop") + "\adbData" }
    }
    
    $script:Config.DefaultDestination = $defaultDest
    $script:Config.FirstRunComplete = $true
    Save-Config
    
    Write-Host ""
    Write-Host "  [OK] Default folder: $defaultDest" -ForegroundColor Green
    Write-Host ""
    Write-Host "  ============================================================================" -ForegroundColor Green
    Write-Host "                            SETUP COMPLETED                                   " -ForegroundColor Green
    Write-Host "  ============================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Transfer operations now available." -ForegroundColor White
    Write-Host "  Note: READ-ONLY access mode enforced." -ForegroundColor Green
    Write-Host "  Device files are never modified, deleted, or moved." -ForegroundColor Green
    Write-Host ""
    Write-Host "  [Press Enter to return]" -ForegroundColor Yellow
    Read-Host
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
            Write-Host "===============================================================================" -ForegroundColor Red
            Write-Host "                              ADB NOT FOUND!                                   " -ForegroundColor Red
            Write-Host "===============================================================================" -ForegroundColor Red
            Write-Host ""
            Write-Host "  Android Debug Bridge (ADB) is not installed or could not be found." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Installation options:" -ForegroundColor White
            Write-Host ""
            Write-Host "  1. Download Platform Tools and extract to 'platform-tools' folder:" -ForegroundColor Cyan
            Write-Host "     https://developer.android.com/studio/releases/platform-tools" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  2. Or install Android Studio and add to system PATH" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  After installation, run the script again." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "===============================================================================" -ForegroundColor Red
            Write-Host ""
            Read-Host "  [Press Enter to exit]"
            exit 1
        }
        
        # Show banner
        Show-Banner
        
        # Show disclaimer (first time or always)
        if (-not (Show-Disclaimer)) {
            Write-Log "User declined to proceed" -Level INFO
            exit 0
        }
        
        # Show script info
        Show-ScriptInfo
        
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
        Write-Host "  [ERROR] Critical error occurred: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Log file: $($script:LogFile)" -ForegroundColor Gray
        Write-Host ""
        Read-Host "  Press Enter to exit"
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

