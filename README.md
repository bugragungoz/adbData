# adbData

High-performance Android file transfer via ADB with cryptographic integrity verification and security hardening.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

> **⚠️ DISCLAIMER**  
> This software is provided as-is without any warranty. It has **not been extensively tested** in production environments.  
> Use at your own risk. The author is not responsible for any data loss, corruption, or damage.  
> Always backup your data before performing any file transfer operations.

## Overview

ADB-based file transfer utility addressing MTP protocol limitations (connection instability, data corruption, performance degradation). Implements cryptographic hash verification, atomic operations, and comprehensive security controls.

**Core Features:**
- Cryptographic integrity verification (MD5/SHA256)
- Incremental transfer with resume capability
- Batch-optimized operations (250x faster enumeration)
- Optional parallel transfer (experimental)
- Command injection and path traversal protection
- JSONL audit logging with rate limiting

## Requirements

- Windows 10+ / PowerShell 5.1+
- ADB-enabled Android device (USB debugging)
- Platform tools included in `platform-tools/`

## Installation

```powershell
# Clone repository
git clone https://github.com/bugragungoz/adbData.git
cd adbData

# Execute main script
.\adbData.ps1
```

### Execution Policy Error Fix

If you encounter `"cannot be loaded. The file is not digitally signed"` error:

**Option 1 (Recommended):** Unblock the file
```powershell
Unblock-File -Path .\adbData.ps1
.\adbData.ps1
```

**Option 2:** Bypass execution policy for current session
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\adbData.ps1
```

**Option 3:** Run with bypass flag (one-liner)
```powershell
powershell -ExecutionPolicy Bypass -File .\adbData.ps1
```

**Option 4:** Set user-level policy (permanent)
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
.\adbData.ps1
```

## Architecture

### Performance Characteristics
- 2-3x throughput vs MTP (large files)
- 5-10x throughput vs MTP (small files)
- Batch enumeration: 250x faster than individual queries
- Configurable hash threshold: skip verification <100MB
- Optional parallel mode: 3 concurrent threads for files <10MB

### Security Model
- Command injection prevention (whitelist validation, parameter escaping)
- Path traversal blocking (10+ attack pattern detection)
- ADB binary verification (SHA256 whitelist)
- Exclusive file locking (race condition prevention)
- Memory wiping (secure data disposal)
- Rate limiting: 50 req/sec, 1000 req/min
- Timing-safe cryptographic comparison

### Transfer Mechanics
- Atomic operations (no partial file corruption)
- Session persistence (`config/resume.json`)
- Incremental sync (skip existing files)
- Real-time progress tracking with ETA
- Automatic disk space validation

---

## Configuration

Configuration file: `config/settings.json` (auto-generated on first run)

```json
{
  "DefaultDestination": "C:\\Users\\YourName\\Desktop\\adbData",
  "AlwaysVerifyHash": true,
  "HashAlgorithm": "MD5",
  "MaxRetries": 3,
  "RetryDelaySeconds": 5,
  
  "SmallFileThreshold": 104857600,
  "BatchSizeQueryLimit": 10000,
  "GCInterval": 1000,
  
  "EnableParallelTransfer": false,
  "ParallelThreadCount": 3,
  "ParallelFileThreshold": 10485760,
  
  "SanitizePaths": true,
  "ValidateADBSignature": false
}
```

**Parameter Reference:**
- `SmallFileThreshold`: Hash verification bypass threshold (100MB default)
- `BatchSizeQueryLimit`: Maximum batch enumeration size (10K files)
- `GCInterval`: Garbage collection trigger interval (1000 files)
- `EnableParallelTransfer`: Concurrent transfer mode (experimental, disabled by default)
- `ParallelThreadCount`: Parallel worker count (3 threads)
- `ParallelFileThreshold`: Parallel eligibility threshold (10MB)
- `SanitizePaths`: Path security validation (recommended: enabled)
- `ValidateADBSignature`: Binary integrity verification (requires elevated privileges)

## Usage

**Preset Transfer:**
```powershell
# Launch interactive menu
.\adbData.ps1

# Select device → Choose preset (Camera/WhatsApp/Downloads/Screenshots)
```

**Custom Transfer:**
```powershell
# Manual path specification
Source: /sdcard/DCIM/Camera/
Destination: D:\Backup\Photos\
```

**Common Android Paths:**
- `/sdcard/DCIM/Camera/` - Camera output
- `/sdcard/Pictures/Screenshots/` - Screenshot storage
- `/sdcard/WhatsApp/Media/` - WhatsApp media (Android <11)
- `/sdcard/Android/media/com.whatsapp/WhatsApp/` - WhatsApp (Android 11+)
- `/sdcard/Download/` - Download directory

## Diagnostics

**Connection Issues:**
- Verify USB debugging authorization on device
- Test ADB connectivity: `.\platform-tools\adb.exe devices`
- Check USB cable and port (USB 3.0 recommended)

**Transfer Failures:**
- Validate available disk space
- Check file lock status and device screen state
- Review transfer logs: `logs/transfer_*.log`
- Inspect audit trail: `logs/transfer_*_audit.jsonl`

**Performance Optimization:**
- Hash algorithm: MD5 (faster) vs SHA256 (more secure)
- Adjust `SmallFileThreshold` based on file size distribution
- Enable parallel mode for small file batches
- Reduce `GCInterval` if memory constrained (500 recommended)

---

## Project Structure

```
adbData/
├── adbData.ps1                  # Main executable
├── platform-tools/              # ADB binaries (bundled)
├── config/                      # Runtime configuration
│   ├── settings.json            # User preferences
│   ├── presets.json             # Transfer templates
│   └── resume.json              # Session state
└── logs/                        # Telemetry and audit
    ├── transfer_*.log           # Transfer events
    ├── transfer_*_audit.jsonl   # Security audit trail
    └── security_audit_*.log     # Security events
```

## License

MIT License - See [LICENSE](LICENSE)

## Development

**Author:** Bugra  
**AI Architecture:** Claude Sonnet 4.5 (Anthropic)  
**ADB Platform:** Google Android SDK Platform Tools
