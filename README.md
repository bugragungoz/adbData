# adbData

Reliable file transfer between Android and Windows via ADB, with integrity verification and security features.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

---

## Why This Tool?

Windows MTP has reliability issues: frequent freezing with large files, data corruption, slow transfers, connection drops. This tool uses ADB for stable, high-speed transfers with integrity verification.

**Key Features:**
- Hash verification (MD5/SHA256) for data integrity
- High performance with optimized batch operations
- Security: command injection protection, path traversal prevention, input validation
- **Resume capability**: Skip existing files, interrupted transfer recovery
- **Incremental transfers**: Automatically skip already-transferred files
- **Parallel transfers**: Optional batch-based concurrent transfers (experimental)
- Smart presets for common scenarios

---

## Quick Start

1. Download: `adbData_v1.0.0.zip`
2. Extract to any folder
3. Right-click `adbData.ps1` → **"Run with PowerShell"**
4. Follow setup wizard
5. Start transferring

**Requirements:**
- Windows 10+ with PowerShell 5.1+
- Android device with USB debugging enabled
- ADB platform tools (included in `platform-tools/`)

---

## Features

### Core Functionality
- **Smart Presets**: Camera, WhatsApp, Downloads, Screenshots
- **Custom Transfers**: Any folder with recursive support
- **Integrity Verification**: Hash-based (configurable threshold)
- **Progress Tracking**: Real-time speed and ETA
- **Atomic Operations**: No corrupted partial files
- **Resume/Incremental**: Skip existing files, resume interrupted transfers
- **Session Tracking**: Transfer history with completion status

### Security
- Command injection protection (whitelist validation, escaping)
- Path traversal prevention (10+ attack patterns blocked)
- ADB binary integrity check (SHA256 whitelist)
- Race condition protection (exclusive file locking)
- Memory security (secure data wiping)
- Rate limiting (50/sec, 1000/min)
- Comprehensive audit logging (JSONL format)
- Input validation framework
- Timing-safe hash comparison
- Structured error handling

### Performance
- 2-3x faster than MTP for large files
- 5-10x faster for many small files
- Batch queries (250x faster file scanning)
- Smart hash skipping (<100MB files)
- Memory leak prevention
- Automatic disk space check
- Optional parallel transfers for small files (experimental)
- Skip existing files for faster re-runs

---

## Usage

### Quick Transfer
1. Select device
2. Choose preset (e.g., Camera Photos)
3. Wait for completion

### Custom Transfer
1. Select device
2. Enter source path (e.g., `/sdcard/DCIM/Camera/`)
3. Enter destination path (e.g., `D:\Photos\`)
4. Configure options
5. Transfer

### Common Android Paths
- `/sdcard/DCIM/Camera/` - Camera photos/videos
- `/sdcard/Pictures/Screenshots/` - Screenshots
- `/sdcard/WhatsApp/Media/` - WhatsApp media (Android <11)
- `/sdcard/Android/media/com.whatsapp/WhatsApp/` - WhatsApp (Android 11+)
- `/sdcard/Download/` - Downloads

---

## Configuration

Settings: `config/settings.json`

```json
{
  "DefaultDestination": "C:\\Users\\YourName\\Desktop\\adbData",
  "AlwaysVerifyHash": true,
  "HashAlgorithm": "MD5",
  "MaxRetries": 3,
  "RetryDelaySeconds": 5,
  "ShowProgressBar": true,
  
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

**Key Parameters:**
- `SmallFileThreshold`: Skip hash for files under this size (bytes)
- `BatchSizeQueryLimit`: Max files per batch query
- `GCInterval`: Garbage collection frequency (files)
- `EnableParallelTransfer`: Enable parallel transfers (experimental, default: false)
- `ParallelThreadCount`: Number of concurrent transfers (default: 3)
- `ParallelFileThreshold`: Only parallel for files under this size (10MB)
- `SanitizePaths`: Enable path security checks (recommended: true)
- `ValidateADBSignature`: Verify ADB binary signature (requires admin)

---

## Troubleshooting

**Device Not Found:**
- Check USB debugging enabled
- Accept "Allow USB debugging" prompt
- Try different USB port
- Run `adb devices` to verify connection

**Transfer Failed:**
- Check disk space
- Ensure files not locked
- Keep device awake
- Review logs in `logs/` folder

**Hash Verification Slow:**
- Use MD5 instead of SHA256
- Increase `SmallFileThreshold`
- Use USB 3.0

**High Memory Usage:**
- Decrease `GCInterval` to 500
- Transfer in smaller batches

---

## Project Structure

```
adbData/
├── adbData.ps1                  # Main script (all-in-one)
├── README.md                    # Quick reference
├── LICENSE                      # MIT License
├── platform-tools/              # ADB binaries (included)
│   ├── adb.exe
│   ├── AdbWinApi.dll
│   └── AdbWinUsbApi.dll
├── config/                      # Auto-generated
│   ├── settings.json
│   ├── presets.json
│   └── resume.json              # Transfer session tracking
└── logs/                        # Transfer & audit logs
    ├── transfer_*.log
    ├── transfer_*_audit.jsonl
    └── security_audit_*.log
```

---

## License

MIT License - see [LICENSE](LICENSE) file.

---

## Credits

- Developer: Bugra
- AI Assistant: Claude Sonnet 4.5 (Anthropic)
- ADB: Google Android Platform Tools
