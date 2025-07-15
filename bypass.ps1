# Set output encoding to UTF-8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Color definitions
$RED = "`e[31m"
$GREEN = "`e[32m"
$YELLOW = "`e[33m"
$BLUE = "`e[34m"
$NC = "`e[0m"

# Configuration file paths
$STORAGE_FILE = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
$BACKUP_DIR = "$env:APPDATA\Cursor\User\globalStorage\backups"

# Function to check file accessibility
function Test-FileAccessibility {
    param(
        [string]$FilePath
    )

    Write-Host "$BLUE🔐 [Permission Check]$NC Checking file access: $(Split-Path $FilePath -Leaf)"

    if (-not (Test-Path $FilePath)) {
        Write-Host "$RED❌ [Error]$NC File does not exist"
        return $false
    }

    # Check if file is locked
    try {
        $fileStream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
        $fileStream.Close()
        Write-Host "$GREEN✅ [Permission]$NC File is readable and writable, not locked"
        return $true
    } catch [System.IO.IOException] {
        Write-Host "$RED❌ [Locked]$NC File is locked by another process: $($_.Exception.Message)"
        return $false
    } catch [System.UnauthorizedAccessException] {
        Write-Host "$YELLOW⚠️ [Permission]$NC File access restricted, attempting to modify permissions..."

        # Attempt to modify file permissions
        try {
            $file = Get-Item $FilePath
            if ($file.IsReadOnly) {
                $file.IsReadOnly = $false
                Write-Host "$GREEN✅ [Fixed]$NC Removed read-only attribute"
            }

            # Test again
            $fileStream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
            $fileStream.Close()
            Write-Host "$GREEN✅ [Permission]$NC Permission fixed successfully"
            return $true
        } catch {
            Write-Host "$RED❌ [Permission]$NC Failed to fix permissions: $($_.Exception.Message)"
            return $false
        }
    } catch {
        Write-Host "$RED❌ [Error]$NC Unknown error: $($_.Exception.Message)"
        return $false
    }
}

# Function to modify machine code configuration
function Modify-MachineCodeConfig {
    param(
        [string]$Mode = "MODIFY_ONLY"
    )

    Write-Host ""
    Write-Host "$GREEN🛠️ [Configuration]$NC Modifying machine code configuration..."

    $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"

    # Enhanced configuration file check
    if (-not (Test-Path $configPath)) {
        Write-Host "$RED❌ [Error]$NC Configuration file does not exist: $configPath"
        Write-Host ""
        Write-Host "$YELLOW💡 [Solution]$NC Please try the following steps:"
        Write-Host "$BLUE  1️⃣ Launch Cursor manually$NC"
        Write-Host "$BLUE  2️⃣ Wait for Cursor to fully load (about 30 seconds)$NC"
        Write-Host "$BLUE  3️⃣ Close Cursor$NC"
        Write-Host "$BLUE  4️⃣ Re-run this script$NC"
        Write-Host ""
        return $false
    }

    # Check file permissions and lock status
    if (-not (Test-FileAccessibility -FilePath $configPath)) {
        Write-Host "$RED❌ [Error]$NC Unable to access configuration file, it may be locked or permissions are insufficient"
        return $false
    }

    # Validate configuration file format and display structure
    try {
        Write-Host "$BLUE🔍 [Validation]$NC Checking configuration file format..."
        $originalContent = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
        $config = $originalContent | ConvertFrom-Json -ErrorAction Stop
        Write-Host "$GREEN✅ [Validation]$NC Configuration file format is valid"

        # Display current telemetry properties
        Write-Host "$BLUE📋 [Current Config]$NC Checking existing telemetry properties:"
        $telemetryProperties = @('telemetry.machineId', 'telemetry.macMachineId', 'telemetry.devDeviceId', 'telemetry.sqmId')
        foreach ($prop in $telemetryProperties) {
            if ($config.PSObject.Properties[$prop]) {
                $value = $config.$prop
                $displayValue = if ($value.Length -gt 20) { "$($value.Substring(0,20))..." } else { $value }
                Write-Host "$GREEN  ✓ ${prop}$NC = $displayValue"
            } else {
                Write-Host "$YELLOW  - ${prop}$NC (does not exist, will create)"
            }
        }
        Write-Host ""
    } catch {
        Write-Host "$RED❌ [Error]$NC Configuration file format error: $($_.Exception.Message)"
        Write-Host "$YELLOW💡 [Suggestion]$NC Configuration file may be corrupted, consider manual intervention"
        return $false
    }

    # Implement atomic file operations with retry mechanism
    $maxRetries = 3
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
        $retryCount++
        Write-Host ""
        Write-Host "$BLUE🔄 [Attempt]$NC Attempt $retryCount/$maxRetries..."

        try {
            # Display operation progress
            Write-Host "$BLUE⏳ [Progress]$NC 1/6 - Generating new device identifiers..."

            # Generate new IDs
            $MAC_MACHINE_ID = [System.Guid]::NewGuid().ToString()
            $UUID = [System.Guid]::NewGuid().ToString()
            $prefixBytes = [System.Text.Encoding]::UTF8.GetBytes("auth0|user_")
            $prefixHex = -join ($prefixBytes | ForEach-Object { '{0:x2}' -f $_ })
            $randomBytes = New-Object byte[] 32
            $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
            $rng.GetBytes($randomBytes)
            $randomPart = [System.BitConverter]::ToString($randomBytes) -replace '-',''
            $rng.Dispose()
            $MACHINE_ID = "${prefixHex}${randomPart}"
            $SQM_ID = "{$([System.Guid]::NewGuid().ToString().ToUpper())}"

            Write-Host "$GREEN✅ [Progress]$NC 1/6 - Device identifiers generated"

            Write-Host "$BLUE⏳ [Progress]$NC 2/6 - Creating backup directory..."

            # Backup original values
            $backupDir = "$env:APPDATA\Cursor\User\globalStorage\backups"
            if (-not (Test-Path $backupDir)) {
                New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction Stop | Out-Null
            }

            $backupName = "storage.json.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')_retry$retryCount"
            $backupPath = "$backupDir\$backupName"

            Write-Host "$BLUE⏳ [Progress]$NC 3/6 - Backing up original configuration..."
            Copy-Item $configPath $backupPath -ErrorAction Stop

            # Verify backup
            if (Test-Path $backupPath) {
                $backupSize = (Get-Item $backupPath).Length
                $originalSize = (Get-Item $configPath).Length
                if ($backupSize -eq $originalSize) {
                    Write-Host "$GREEN✅ [Progress]$NC 3/6 - Configuration backed up successfully: $backupName"
                } else {
                    Write-Host "$YELLOW⚠️ [Warning]$NC Backup file size mismatch, continuing..."
                }
            } else {
                throw "Backup file creation failed"
            }

            Write-Host "$BLUE⏳ [Progress]$NC 4/6 - Reading original configuration into memory..."

            # Atomic operation: Read original content into memory
            $originalContent = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
            $config = $originalContent | ConvertFrom-Json -ErrorAction Stop

            Write-Host "$BLUE⏳ [Progress]$NC 5/6 - Updating configuration in memory..."

            # Update configuration values safely
            $propertiesToUpdate = @{
                'telemetry.machineId' = $MACHINE_ID
                'telemetry.macMachineId' = $MAC_MACHINE_ID
                'telemetry.devDeviceId' = $UUID
                'telemetry.sqmId' = $SQM_ID
            }

            foreach ($property in $propertiesToUpdate.GetEnumerator()) {
                $key = $property.Key
                $value = $property.Value

                if ($config.PSObject.Properties[$key]) {
                    $config.$key = $value
                    Write-Host "$BLUE  ✓ Updating property: ${key}$NC"
                } else {
                    $config | Add-Member -MemberType NoteProperty -Name $key -Value $value -Force
                    Write-Host "$BLUE  + Adding property: ${key}$NC"
                }
            }

            Write-Host "$BLUE⏳ [Progress]$NC 6/6 - Atomically writing new configuration file..."

            # Atomic operation: Write to temp file
            $tempPath = "$configPath.tmp"
            $updatedJson = $config | ConvertTo-Json -Depth 10
            [System.IO.File]::WriteAllText($tempPath, $updatedJson, [System.Text.Encoding]::UTF8)

            # Verify temp file
            $tempContent = Get-Content $tempPath -Raw -Encoding UTF8
            $tempConfig = $tempContent | ConvertFrom-Json

            # Verify all properties
            $tempVerificationPassed = $true
            foreach ($property in $propertiesToUpdate.GetEnumerator()) {
                $key = $property.Key
                $expectedValue = $property.Value
                $actualValue = $tempConfig.$key

                if ($actualValue -ne $expectedValue) {
                    $tempVerificationPassed = $false
                    Write-Host "$RED  ✗ Temp file verification failed: ${key}$NC"
                    break
                }
            }

            if (-not $tempVerificationPassed) {
                Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
                throw "Temp file verification failed"
            }

            # Atomic replace: Delete original, rename temp
            Remove-Item $configPath -Force
            Move-Item $tempPath $configPath

            # Set file to read-only (optional)
            $file = Get-Item $configPath
            $file.IsReadOnly = $false

            # Final verification
            Write-Host "$BLUE🔍 [Final Verification]$NC Verifying new configuration file..."

            $verifyContent = Get-Content $configPath -Raw -Encoding UTF8
            $verifyConfig = $verifyContent | ConvertFrom-Json

            $verificationPassed = $true
            $verificationResults = @()

            foreach ($property in $propertiesToUpdate.GetEnumerator()) {
                $key = $property.Key
                $expectedValue = $property.Value
                $actualValue = $verifyConfig.$key

                if ($actualValue -eq $expectedValue) {
                    $verificationResults += "✓ ${key}: Verification passed"
                } else {
                    $verificationResults += "✗ ${key}: Verification failed (Expected: ${expectedValue}, Actual: ${actualValue})"
                    $verificationPassed = $false
                }
            }

            Write-Host "$BLUE📋 [Verification Details]$NC"
            foreach ($result in $verificationResults) {
                Write-Host "   $result"
            }

            if ($verificationPassed) {
                Write-Host "$GREEN✅ [Success]$NC Attempt $retryCount succeeded!"
                Write-Host ""
                Write-Host "$GREEN🎉 [Completed]$NC Machine code configuration modified!"
                Write-Host "$BLUE📋 [Details]$NC Updated the following identifiers:"
                Write-Host "   🔹 machineId: $MACHINE_ID"
                Write-Host "   🔹 macMachineId: $MAC_MACHINE_ID"
                Write-Host "   🔹 devDeviceId: $UUID"
                Write-Host "   🔹 sqmId: $SQM_ID"
                Write-Host ""
                Write-Host "$GREEN💾 [Backup]$NC Original configuration backed up to: $backupName"
                return $true
            } else {
                Write-Host "$RED❌ [Failure]$NC Attempt $retryCount verification failed"
                if ($retryCount -lt $maxRetries) {
                    Write-Host "$BLUE🔄 [Restore]$NC Restoring backup, preparing to retry..."
                    Copy-Item $backupPath $configPath -Force
                    Start-Sleep -Seconds 2
                    continue
                } else {
                    Write-Host "$RED❌ [Final Failure]$NC All retries failed, restoring original configuration"
                    Copy-Item $backupPath $configPath -Force
                    return $false
                }
            }

        } catch {
            Write-Host "$RED❌ [Exception]$NC Attempt $retryCount failed: $($_.Exception.Message)"
            Write-Host "$BLUE💡 [Debug Info]$NC Error type: $($_.Exception.GetType().FullName)"

            # Clean up temp file
            if (Test-Path "$configPath.tmp") {
                Remove-Item "$configPath.tmp" -Force -ErrorAction SilentlyContinue
            }

            if ($retryCount -lt $maxRetries) {
                Write-Host "$BLUE🔄 [Restore]$NC Restoring backup, preparing to retry..."
                if (Test-Path $backupPath) {
                    Copy-Item $backupPath $configPath -Force
                }
                Start-Sleep -Seconds 3
                continue
            } else {
                Write-Host "$RED❌ [Final Failure]$NC All retries failed"
                if (Test-Path $backupPath) {
                    Write-Host "$BLUE🔄 [Restore]$NC Restoring backup configuration..."
                    try {
                        Copy-Item $backupPath $configPath -Force
                        Write-Host "$GREEN✅ [Restore]$NC Original configuration restored"
                    } catch {
                        Write-Host "$RED❌ [Error]$NC Failed to restore backup: $($_.Exception.Message)"
                    }
                }
                return $false
            }
        }
    }

    Write-Host "$RED❌ [Final Failure]$NC Failed to complete modification after $maxRetries attempts"
    return $false
}

# Function to update MachineGuid in the registry
function Update-MachineGuid {
    try {
        Write-Host "$BLUE🔧 [Registry]$NC Modifying system registry MachineGuid..."

        # Check if registry path exists, create if not
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        if (-not (Test-Path $registryPath)) {
            Write-Host "$YELLOW⚠️ [Warning]$NC Registry path does not exist: $registryPath, creating..."
            New-Item -Path $registryPath -Force | Out-Null
            Write-Host "$GREEN✅ [Info]$NC Registry path created successfully"
        }

        # Get current MachineGuid
        $originalGuid = ""
        try {
            $currentGuid = Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction SilentlyContinue
            if ($currentGuid) {
                $originalGuid = $currentGuid.MachineGuid
                Write-Host "$GREEN✅ [Info]$NC Current registry value:"
                Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
                Write-Host "    MachineGuid    REG_SZ    $originalGuid"
            } else {
                Write-Host "$YELLOW⚠️ [Warning]$NC MachineGuid value does not exist, will create new value"
            }
        } catch {
            Write-Host "$YELLOW⚠️ [Warning]$NC Failed to read registry: $($_.Exception.Message)"
            Write-Host "$YELLOW⚠️ [Warning]$NC Will attempt to create new MachineGuid value"
        }

        # Create backup file
        $backupFile = $null
        if ($originalGuid) {
            $backupFile = "$BACKUP_DIR\MachineGuid_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
            Write-Host "$BLUE💾 [Backup]$NC Backing up registry..."
            $backupResult = Start-Process "reg.exe" -ArgumentList "export", "`"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`"", "`"$backupFile`"" -NoNewWindow -Wait -PassThru

            if ($backupResult.ExitCode -eq 0) {
                Write-Host "$GREEN✅ [Backup]$NC Registry key backed up to: $backupFile"
            } else {
                Write-Host "$YELLOW⚠️ [Warning]$NC Backup creation failed, continuing..."
                $backupFile = $null
            }
        }

        # Generate new GUID
        $newGuid = [System.Guid]::NewGuid().ToString()
        Write-Host "$BLUE🔄 [Generate]$NC New MachineGuid: $newGuid"

        # Update or create registry value
        Set-ItemProperty -Path $registryPath -Name MachineGuid -Value $newGuid -Force -ErrorAction Stop

        # Verify update
        $verifyGuid = (Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop).MachineGuid
        if ($verifyGuid -ne $newGuid) {
            throw "Registry verification failed: Updated value ($verifyGuid) does not match expected value ($newGuid)"
        }

        Write-Host "$GREEN✅ [Success]$NC Registry updated successfully:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
        Write-Host "    MachineGuid    REG_SZ    $newGuid"
        return $true
    } catch {
        Write-Host "$RED❌ [Error]$NC Registry operation failed: $($_.Exception.Message)"

        # Attempt to restore backup
        if ($backupFile -and (Test-Path $backupFile)) {
            Write-Host "$YELLOW🔄 [Restore]$NC Restoring from backup..."
            $restoreResult = Start-Process "reg.exe" -ArgumentList "import", "`"$backupFile`"" -NoNewWindow -Wait -PassThru

            if ($restoreResult.ExitCode -eq 0) {
                Write-Host "$GREEN✅ [Restore Success]$NC Original registry value restored"
            } else {
                Write-Host "$RED❌ [Error]$NC Restore failed, please manually import backup file: $backupFile"
            }
        } else {
            Write-Host "$YELLOW⚠️ [Warning]$NC No backup file found or backup creation failed, cannot restore automatically"
        }

        return $false
    }
}

# Function to modify Cursor JS files (Method 1: IOPlatformUUID)
function Modify-CursorJSFiles {
    Write-Host ""
    Write-Host "$BLUE🔧 [Core Modification]$NC Modifying Cursor core JS files for device identification bypass..."
    Write-Host ""

    # Cursor application path
    $cursorAppPath = "${env:LOCALAPPDATA}\Programs\Cursor"
    if (-not (Test-Path $cursorAppPath)) {
        $alternatePaths = @(
            "${env:ProgramFiles}\Cursor",
            "${env:ProgramFiles(x86)}\Cursor",
            "${env:USERPROFILE}\AppData\Local\Programs\Cursor"
        )

        foreach ($path in $alternatePaths) {
            if (Test-Path $path) {
                $cursorAppPath = $path
                break
            }
        }

        if (-not (Test-Path $cursorAppPath)) {
            Write-Host "$RED❌ [Error]$NC Cursor application path not found"
            Write-Host "$YELLOW💡 [Tip]$NC Please ensure Cursor is installed correctly"
            return $false
        }
    }

    Write-Host "$GREEN✅ [Found]$NC Cursor installation path: $cursorAppPath"

    # Generate new device identifiers
    $newUuid = [System.Guid]::NewGuid().ToString().ToLower()
    $machineId = "auth0|user_$([System.Web.Security.Membership]::GeneratePassword(32, 0))"
    $deviceId = [System.Guid]::NewGuid().ToString().ToLower()
    $macMachineId = [System.Web.Security.Membership]::GeneratePassword(64, 0)

    Write-Host "$GREEN🔑 [Generated]$NC New device identifiers generated"

    # Target JS files
    $jsFiles = @(
        "$cursorAppPath\resources\app\out\vs\workbench\api\node\extensionHostProcess.js",
        "$cursorAppPath\resources\app\out\main.js",
        "$cursorAppPath\resources\app\out\vs\code\node\cliProcessMain.js"
    )

    $modifiedCount = 0
    $needModification = $false

    # Check if modification is needed
    Write-Host "$BLUE🔍 [Check]$NC Checking JS file modification status..."
    foreach ($file in $jsFiles) {
        if (-not (Test-Path $file)) {
            Write-Host "$YELLOW⚠️ [Warning]$NC File does not exist: $(Split-Path $file -Leaf)"
            continue
        }

        $content = Get-Content $file -Raw -ErrorAction SilentlyContinue
        if ($content -and $content -notmatch "return crypto\.randomUUID\(\)") {
            Write-Host "$BLUE📝 [Needs]$NC File needs modification: $(Split-Path $file -Leaf)"
            $needModification = $true
            break
        } else {
            Write-Host "$GREEN✅ [Modified]$NC File already modified: $(Split-Path $file -Leaf)"
        }
    }

    if (-not $needModification) {
        Write-Host "$GREEN✅ [Skip]$NC All JS files have been modified previously, no action needed"
        return $true
    }

    # Create backup
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = "$env:TEMP\Cursor_JS_Backup_$timestamp"

    Write-Host "$BLUE💾 [Backup]$NC Creating Cursor JS file backups..."
    try {
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        foreach ($file in $jsFiles) {
            if (Test-Path $file) {
                $fileName = Split-Path $file -Leaf
                Copy-Item $file "$backupPath\$fileName" -Force
            }
        }
        Write-Host "$GREEN✅ [Backup]$NC Backup created successfully: $backupPath"
    } catch {
        Write-Host "$RED❌ [Error]$NC Failed to create backup: $($_.Exception.Message)"
        return $false
    }

    # Modify JS files
    Write-Host "$BLUE🔧 [Modify]$NC Modifying JS files..."

    foreach ($file in $jsFiles) {
        if (-not (Test-Path $file)) {
            Write-Host "$YELLOW⚠️ [Skip]$NC File does not exist: $(Split-Path $file -Leaf)"
            continue
        }

        Write-Host "$BLUE📝 [Processing]$NC Processing: $(Split-Path $file -Leaf)"

        try {
            $content = Get-Content $file -Raw -Encoding UTF8

            # Check if already modified
            if ($content -match "return crypto\.randomUUID\(\)" -or $content -match "// Cursor ID Modification Tool Injection") {
                Write-Host "$GREEN✅ [Skip]$NC File already modified"
                $modifiedCount++
                continue
            }

            # Method 1: IOPlatformUUID modification
            if ($content -match "IOPlatformUUID") {
                Write-Host "$BLUE🔍 [Found]$NC Found IOPlatformUUID keyword"

                # Inject code at the beginning
                $injectCode = @"
// Cursor ID Modification Tool Injection - $(Get-Date)
import crypto from 'crypto';
crypto.randomUUID = function() { return '$newUuid'; };
globalThis.getMachineId = function() { return '$machineId'; };
globalThis.getDeviceId = function() { return '$deviceId'; };
globalThis.macMachineId = '$macMachineId';
if (typeof window !== 'undefined') {
    window.getMachineId = globalThis.getMachineId;
    window.getDeviceId = globalThis.getDeviceId;
    window.macMachineId = globalThis.macMachineId;
}
console.log('Cursor device identifiers hijacked successfully');
"@

                $content = $injectCode + $content
                Write-Host "$GREEN✅ [Success]$NC General injection method applied successfully"
                $modifiedCount++
            } else {
                Write-Host "$YELLOW⚠️ [Warning]$NC IOPlatformUUID not found, skipping file"
                continue
            }

            # Write modified content
            Set-Content -Path $file -Value $content -Encoding UTF8 -NoNewline
            Write-Host "$GREEN✅ [Completed]$NC File modification completed: $(Split-Path $file -Leaf)"

        } catch {
            Write-Host "$RED❌ [Error]$NC Failed to modify file: $($_.Exception.Message)"
            $fileName = Split-Path $file -Leaf
            $backupFile = "$backupPath\$fileName"
            if (Test-Path $backupFile) {
                Copy-Item $backupFile $file -Force
                Write-Host "$YELLOW🔄 [Restore]$NC Restored file from backup"
            }
        }
    }

    if ($modifiedCount -gt 0) {
        Write-Host ""
        Write-Host "$GREEN🎉 [Completed]$NC Successfully modified $modifiedCount JS files"
        Write-Host "$BLUE💾 [Backup]$NC Original files backed up at: $backupPath"
        Write-Host "$BLUE💡 [Info]$NC JavaScript injection enabled for device identification bypass"
        return $true
    } else {
        Write-Host "$RED❌ [Failure]$NC No files were successfully modified"
        return $false
    }
}

# Check administrator privileges
function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "$RED[Error]$NC Please run this script as an administrator"
    Write-Host "Right-click the script and select 'Run as administrator'"
    Read-Host "Press Enter to exit"
    exit 1
}

# Display logo
Clear-Host
Write-Host @"

    ██████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ 
   ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔══██╗
   ██║     ██║   ██║██████╔╝███████╗██║   ██║██████╔╝
   ██║     ██║   ██║██╔══██╗╚════██║██║   ██║██╔══██╗
   ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝██║  ██║
    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝

"@
Write-Host "$BLUE================================$NC"
Write-Host "$GREEN🚀 Cursor Trial Pro Extension Tool $NC"
Write-Host "$BLUE================================$NC"

# User confirmation
Write-Host ""
Write-Host "$GREEN🤔 [Confirmation]$NC Please confirm you want to execute the script"
$confirmation = Read-Host "Continue execution? (Enter y or yes to continue, any other key to exit)"
if ($confirmation -notmatch "^(y|yes)$") {
    Write-Host "$YELLOW👋 [Exit]$NC User canceled execution, exiting script"
    Read-Host "Press Enter to exit"
    exit 0
}
Write-Host "$GREEN✅ [Confirmation]$NC User confirmed execution"
Write-Host ""

# Ensure backup directory exists
if (-not (Test-Path $BACKUP_DIR)) {
    try {
        New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
        Write-Host "$GREEN✅ [Backup Directory]$NC Backup directory created: $BACKUP_DIR"
    } catch {
        Write-Host "$YELLOW⚠️ [Warning]$NC Failed to create backup directory: $($_.Exception.Message)"
    }
}

# Execute Modify Machine Code Only
Write-Host "$GREEN🚀 [Start]$NC Starting machine code modification..."

# Execute machine code modification
$configSuccess = Modify-MachineCodeConfig -Mode "MODIFY_ONLY"

if ($configSuccess) {
    Write-Host ""
    Write-Host "$GREEN🎉 [Configuration]$NC Machine code configuration modified successfully!"

    # Modify registry
    Write-Host "$BLUE🔧 [Registry]$NC Modifying system registry..."
    $registrySuccess = Update-MachineGuid

    # JavaScript injection
    Write-Host ""
    Write-Host "$BLUE🔧 [Device ID Bypass]$NC Executing JavaScript injection..."
    Write-Host "$BLUE💡 [Info]$NC This modifies Cursor core JS files for deeper device identification bypass"
    $jsSuccess = Modify-CursorJSFiles

    if ($registrySuccess) {
        Write-Host "$GREEN✅ [Registry]$NC System registry modified successfully"

        if ($jsSuccess) {
            Write-Host "$GREEN✅ [JavaScript Injection]$NC JavaScript injection executed successfully"
            Write-Host ""
            Write-Host "$GREEN🎉 [Completed]$NC All machine code modifications completed!"
            Write-Host "$BLUE📋 [Details]$NC Completed the following modifications:"
            Write-Host "$GREEN  ✓ Cursor configuration (storage.json)$NC"
            Write-Host "$GREEN  ✓ System registry (MachineGuid)$NC"
            Write-Host "$GREEN  ✓ JavaScript core injection (device ID bypass)$NC"
        } else {
            Write-Host "$YELLOW⚠️ [JavaScript Injection]$NC JavaScript injection failed, but other modifications succeeded"
            Write-Host ""
            Write-Host "$GREEN🎉 [Completed]$NC Machine code modifications completed!"
            Write-Host "$BLUE📋 [Details]$NC Completed the following modifications:"
            Write-Host "$GREEN  ✓ Cursor configuration (storage.json)$NC"
            Write-Host "$GREEN  ✓ System registry (MachineGuid)$NC"
            Write-Host "$YELLOW  ⚠ JavaScript core injection (partially failed)$NC"
        }

        # Protect configuration file
        Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
        try {
            $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
            $configFile = Get-Item $configPath
            $configFile.IsReadOnly = $true
            Write-Host "$GREEN✅ [Protection]$NC Configuration file set to read-only to prevent Cursor overwriting"
            Write-Host "$BLUE💡 [Tip]$NC File path: $configPath"
        } catch {
            Write-Host "$YELLOW⚠️ [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
            Write-Host "$BLUE💡 [Suggestion]$NC Manually right-click the file → Properties → Check 'Read-only'"
        }
    } else {
        Write-Host "$YELLOW⚠️ [Registry]$NC Registry modification failed, but configuration modified successfully"

        if ($jsSuccess) {
            Write-Host "$GREEN✅ [JavaScript Injection]$NC JavaScript injection executed successfully"
            Write-Host ""
            Write-Host "$YELLOW🎉 [Partially Completed]$NC Configuration and JavaScript injection completed, registry modification failed"
            Write-Host "$BLUE💡 [Suggestion]$NC Administrator privileges may be required for registry modification"
            Write-Host "$BLUE📋 [Details]$NC Completed the following modifications:"
            Write-Host "$GREEN  ✓ Cursor configuration (storage.json)$NC"
            Write-Host "$YELLOW  ⚠ System registry (MachineGuid) - Failed$NC"
            Write-Host "$GREEN  ✓ JavaScript core injection (device ID bypass)$NC"
        } else {
            Write-Host "$YELLOW⚠️ [JavaScript Injection]$NC JavaScript injection failed"
            Write-Host ""
            Write-Host "$YELLOW🎉 [Partially Completed]$NC Configuration modified, registry and JavaScript injection failed"
            Write-Host "$BLUE💡 [Suggestion]$NC Administrator privileges may be required for registry modification"
        }

        # Protect configuration file even if registry modification failed
        Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
        try {
            $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
            $configFile = Get-Item $configPath
            $configFile.IsReadOnly = $true
            Write-Host "$GREEN✅ [Protection]$NC Configuration file set to read-only to prevent Cursor overwriting"
            Write-Host "$BLUE💡 [Tip]$NC File path: $configPath"
        } catch {
            Write-Host "$YELLOW⚠️ [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
            Write-Host "$BLUE💡 [Suggestion]$NC Manually right-click the file → Properties → Check 'Read-only'"
        }
    }

    Write-Host "$BLUE💡 [Tip]$NC You can now start Cursor with the new machine code configuration"
} else {
    Write-Host ""
    Write-Host "$RED❌ [Failure]$NC Machine code modification failed!"
    Write-Host "$YELLOW💡 [Suggestion]$NC Check error messages and retry"
}

# Script completion
Write-Host ""
Write-Host "$GREEN🎉 [Script Completed]$NC Thank you for using the Cursor Machine Code Modification Tool!"
Write-Host "$BLUE💡 [Tip]$NC If you encounter issues, refer to documentation or retry the script"
Write-Host ""
Read-Host "Press Enter to exit"
exit 0
