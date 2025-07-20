# Set output encoding to UTF-8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Configuration file paths
$STORAGE_FILE = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
$BACKUP_DIR = "$env:APPDATA\Cursor\User\globalStorage\backups"

# Function to check file accessibility
function Test-FileAccessibility {
    param(
        [string]$FilePath
    )

    Write-Host "[Permission Check] Checking file access: $(Split-Path $FilePath -Leaf)"

    if (-not (Test-Path $FilePath)) {
        Write-Host "[Error] File does not exist"
        return $false
    }

    # Check if file is locked
    try {
        $fileStream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
        $fileStream.Close()
        Write-Host "[Permission] File is readable and writable, not locked"
        return $true
    } catch [System.IO.IOException] {
        Write-Host "[Error] File is locked by another process: $($_.Exception.Message)"
        return $false
    } catch [System.UnauthorizedAccessException] {
        Write-Host "[Warning] File access restricted, attempting to modify permissions..."

        # Attempt to modify file permissions
        try {
            $file = Get-Item $FilePath
            if ($file.IsReadOnly) {
                $file.IsReadOnly = $false
                Write-Host "[Fixed] Removed read-only attribute"
            }

            # Test again
            $fileStream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
            $fileStream.Close()
            Write-Host "[Permission] Permission fixed successfully"
            return $true
        } catch {
            Write-Host "[Error] Failed to fix permissions: $($_.Exception.Message)"
            return $false
        }
    } catch {
        Write-Host "[Error] Unknown error: $($_.Exception.Message)"
        return $false
    }
}

# Function to modify machine code configuration
function Modify-MachineCodeConfig {
    param(
        [string]$Mode = "MODIFY_ONLY"
    )

    Write-Host ""
    Write-Host "[Configuration] Modifying machine code configuration..."

    $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"

    # Enhanced configuration file check
    if (-not (Test-Path $configPath)) {
        Write-Host "[Error] Configuration file does not exist: $configPath"
        Write-Host ""
        Write-Host "[Solution] Please try the following steps:"
        Write-Host "  1. Launch Cursor manually"
        Write-Host "  2. Wait for Cursor to fully load (about 30 seconds)"
        Write-Host "  3. Close Cursor"
        Write-Host "  4. Re-run this script"
        Write-Host ""
        return $false
    }

    # Check file permissions and lock status
    if (-not (Test-FileAccessibility -FilePath $configPath)) {
        Write-Host "[Error] Unable to access configuration file, it may be locked or permissions are insufficient"
        return $false
    }

    # Validate configuration file format and display structure
    try {
        Write-Host "[Validation] Checking configuration file format..."
        $originalContent = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
        $config = $originalContent | ConvertFrom-Json -ErrorAction Stop
        Write-Host "[Validation] Configuration file format is valid"

        # Display current telemetry properties
        Write-Host "[Current Config] Checking existing telemetry properties:"
        $telemetryProperties = @('telemetry.machineId', 'telemetry.macMachineId', 'telemetry.devDeviceId', 'telemetry.sqmId')
        foreach ($prop in $telemetryProperties) {
            if ($config.PSObject.Properties[$prop]) {
                $value = $config.$prop
                $displayValue = if ($value.Length -gt 20) { "$($value.Substring(0,20))..." } else { $value }
                Write-Host "  ✓ $prop = $displayValue"
            } else {
                Write-Host "  - $prop (does not exist, will create)"
            }
        }
        Write-Host ""
    } catch {
        Write-Host "[Error] Configuration file format error: $($_.Exception.Message)"
        Write-Host "[Suggestion] Configuration file may be corrupted, consider manual intervention"
        return $false
    }

    # Implement atomic file operations with retry mechanism
    $maxRetries = 3
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
        $retryCount++
        Write-Host ""
        Write-Host "[Attempt] Attempt $retryCount/$maxRetries..."

        try {
            # Display operation progress
            Write-Host "[Progress] 1/6 - Generating new device identifiers..."

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

            Write-Host "[Progress] 1/6 - Device identifiers generated"

            Write-Host "[Progress] 2/6 - Creating backup directory..."

            # Backup original values
            $backupDir = "$env:APPDATA\Cursor\User\globalStorage\backups"
            if (-not (Test-Path $backupDir)) {
                New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction Stop | Out-Null
            }

            $backupName = "storage.json.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')_retry$retryCount"
            $backupPath = "$backupDir\$backupName"

            Write-Host "[Progress] 3/6 - Backing up original configuration..."
            Copy-Item $configPath $backupPath -ErrorAction Stop

            # Verify backup
            if (Test-Path $backupPath) {
                $backupSize = (Get-Item $backupPath).Length
                $originalSize = (Get-Item $configPath).Length
                if ($backupSize -eq $originalSize) {
                    Write-Host "[Progress] 3/6 - Configuration backed up successfully: $backupName"
                } else {
                    Write-Host "[Warning] Backup file size mismatch, continuing..."
                }
            } else {
                throw "Backup file creation failed"
            }

            Write-Host "[Progress] 4/6 - Reading original configuration into memory..."

            # Atomic operation: Read original content into memory
            $originalContent = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
            $config = $originalContent | ConvertFrom-Json -ErrorAction Stop

            Write-Host "[Progress] 5/6 - Updating configuration in memory..."

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
                    Write-Host "  ✓ Updating property: $key"
                } else {
                    $config | Add-Member -MemberType NoteProperty -Name $key -Value $value -Force
                    Write-Host "  + Adding property: $key"
                }
            }

            Write-Host "[Progress] 6/6 - Atomically writing new configuration file..."

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
                    Write-Host "[Error] Temp file verification failed: $key"
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
            Write-Host "[Final Verification] Verifying new configuration file..."

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
                    $verificationResults += "✗ ${key}: Verification failed (Expected: $expectedValue, Actual: $actualValue)"
                    $verificationPassed = $false
                }
            }

            Write-Host "[Verification Details]"
            foreach ($result in $verificationResults) {
                Write-Host "   $result"
            }

            if ($verificationPassed) {
                Write-Host "[Success] Attempt $retryCount succeeded!"
                Write-Host ""
                Write-Host "[Completed] Machine code configuration modified!"
                Write-Host "[Details] Updated the following identifiers:"
                Write-Host "   - machineId: $MACHINE_ID"
                Write-Host "   - macMachineId: $MAC_MACHINE_ID"
                Write-Host "   - devDeviceId: $UUID"
                Write-Host "   - sqmId: $SQM_ID"
                Write-Host ""
                Write-Host "[Backup] Original configuration backed up to: $backupName"
                return $true
            } else {
                Write-Host "[Failure] Attempt $retryCount verification failed"
                if ($retryCount -lt $maxRetries) {
                    Write-Host "[Restore] Restoring backup, preparing to retry..."
                    Copy-Item $backupPath $configPath -Force
                    Start-Sleep -Seconds 2
                    continue
                } else {
                    Write-Host "[Final Failure] All retries failed, restoring original configuration"
                    Copy-Item $backupPath $configPath -Force
                    return $false
                }
            }

        } catch {
            Write-Host "[Exception] Attempt $retryCount failed: $($_.Exception.Message)"
            Write-Host "[Debug Info] Error type: $($_.Exception.GetType().FullName)"

            # Clean up temp file
            if (Test-Path "$configPath.tmp") {
                Remove-Item "$configPath.tmp" -Force -ErrorAction SilentlyContinue
            }

            if ($retryCount -lt $maxRetries) {
                Write-Host "[Restore] Restoring backup, preparing to retry..."
                if (Test-Path $backupPath) {
                    Copy-Item $backupPath $configPath -Force
                }
                Start-Sleep -Seconds 3
                continue
            } else {
                Write-Host "[Final Failure] All retries failed"
                if (Test-Path $backupPath) {
                    Write-Host "[Restore] Restoring backup configuration..."
                    try {
                        Copy-Item $backupPath $configPath -Force
                        Write-Host "[Restore] Original configuration restored"
                    } catch {
                        Write-Host "[Error] Failed to restore backup: $($_.Exception.Message)"
                    }
                }
                return $false
            }
        }
    }

    Write-Host "[Final Failure] Failed to complete modification after $maxRetries attempts"
    return $false
}

# Function to update MachineGuid in the registry
function Update-MachineGuid {
    try {
        Write-Host "[Registry] Modifying system registry MachineGuid..."

        # Check if registry path exists, create if not
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        if (-not (Test-Path $registryPath)) {
            Write-Host "[Warning] Registry path does not exist: $registryPath, creating..."
            New-Item -Path $registryPath -Force | Out-Null
            Write-Host "[Info] Registry path created successfully"
        }

        # Get current MachineGuid
        $originalGuid = ""
        try {
            $currentGuid = Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction SilentlyContinue
            if ($currentGuid) {
                $originalGuid = $currentGuid.MachineGuid
                Write-Host "[Info] Current registry value:"
                Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
                Write-Host "    MachineGuid    REG_SZ    $originalGuid"
            } else {
                Write-Host "[Warning] MachineGuid value does not exist, will create new value"
            }
        } catch {
            Write-Host "[Warning] Failed to read registry: $($_.Exception.Message)"
            Write-Host "[Warning] Will attempt to create new MachineGuid value"
        }

        # Create backup file
        $backupFile = $null
        if ($originalGuid) {
            $backupFile = "$BACKUP_DIR\MachineGuid_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
            Write-Host "[Backup] Backing up registry..."
            $backupResult = Start-Process "reg.exe" -ArgumentList "export", "`"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`"", "`"$backupFile`"" -NoNewWindow -Wait -PassThru

            if ($backupResult.ExitCode -eq 0) {
                Write-Host "[Backup] Registry key backed up to: $backupFile"
            } else {
                Write-Host "[Warning] Backup creation failed, continuing..."
                $backupFile = $null
            }
        }

        # Generate new GUID
        $newGuid = [System.Guid]::NewGuid().ToString()
        Write-Host "[Generate] New MachineGuid: $newGuid"

        # Update or create registry value
        Set-ItemProperty -Path $registryPath -Name MachineGuid -Value $newGuid -Force -ErrorAction Stop

        # Verify update
        $verifyGuid = (Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop).MachineGuid
        if ($verifyGuid -ne $newGuid) {
            throw "Registry verification failed: Updated value ($verifyGuid) does not match expected value ($newGuid)"
        }

        Write-Host "[Success] Registry updated successfully:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
        Write-Host "    MachineGuid    REG_SZ    $newGuid"
        return $true
    } catch {
        Write-Host "[Error] Registry operation failed: $($_.Exception.Message)"

        # Attempt to restore backup
        if ($backupFile -and (Test-Path $backupFile)) {
            Write-Host "[Restore] Restoring from backup..."
            $restoreResult = Start-Process "reg.exe" -ArgumentList "import", "`"$backupFile`"" -NoNewWindow -Wait -PassThru

            if ($restoreResult.ExitCode -eq 0) {
                Write-Host "[Restore Success] Original registry value restored"
            } else {
                Write-Host "[Error] Restore failed, please manually import backup file: $backupFile"
            }
        } else {
            Write-Host "[Warning] No backup file found or backup creation failed, cannot restore automatically"
        }

        return $false
    }
}

# Function to modify Cursor JS files (Method 1: IOPlatformUUID)
function Modify-CursorJSFiles {
    Write-Host ""
    Write-Host "[Core Modification] Modifying Cursor core JS files for device identification bypass..."
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
            Write-Host "[Error] Cursor application path not found"
            Write-Host "[Tip] Please ensure Cursor is installed correctly"
            return $false
        }
    }

    Write-Host "[Found] Cursor installation path: $cursorAppPath"

    # Generate new device identifiers
    $newUuid = [System.Guid]::NewGuid().ToString().ToLower()
    $machineId = "auth0|user_$([System.Web.Security.Membership]::GeneratePassword(32, 0))"
    $deviceId = [System.Guid]::NewGuid().ToString().ToLower()
    $macMachineId = [System.Web.Security.Membership]::GeneratePassword(64, 0)

    Write-Host "[Generated] New device identifiers generated"

    # Target JS files
    $jsFiles = @(
        "$cursorAppPath\resources\app\out\vs\workbench\api\node\extensionHostProcess.js",
        "$cursorAppPath\resources\app\out\main.js",
        "$cursorAppPath\resources\app\out\vs\code\node\cliProcessMain.js"
    )

    $modifiedCount = 0
    $needModification = $false

    # Check if modification is needed
    Write-Host "[Check] Checking JS file modification status..."
    foreach ($file in $jsFiles) {
        if (-not (Test-Path $file)) {
            Write-Host "[Warning] File does not exist: $(Split-Path $file -Leaf)"
            continue
        }

        $content = Get-Content $file -Raw -ErrorAction SilentlyContinue
        if ($content -and $content -notmatch "return crypto\.randomUUID\(\)") {
            Write-Host "[Needs] File needs modification: $(Split-Path $file -Leaf)"
            $needModification = $true
            break
        } else {
            Write-Host "[Modified] File already modified: $(Split-Path $file -Leaf)"
        }
    }

    if (-not $needModification) {
        Write-Host "[Skip] All JS files have been modified previously, no action needed"
        return $true
    }

    # Create backup
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = "$env:TEMP\Cursor_JS_Backup_$timestamp"

    Write-Host "[Backup] Creating Cursor JS file backups..."
    try {
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        foreach ($file in $jsFiles) {
            if (Test-Path $file) {
                $fileName = Split-Path $file -Leaf
                Copy-Item $file "$backupPath\$fileName" -Force
            }
        }
        Write-Host "[Backup] Backup created successfully: $backupPath"
    } catch {
        Write-Host "[Error] Failed to create backup: $($_.Exception.Message)"
        return $false
    }

    # Modify JS files
    Write-Host "[Modify] Modifying JS files..."

    foreach ($file in $jsFiles) {
        if (-not (Test-Path $file)) {
            Write-Host "[Skip] File does not exist: $(Split-Path $file -Leaf)"
            continue
        }

        Write-Host "[Processing] Processing: $(Split-Path $file -Leaf)"

        try {
            $content = Get-Content $file -Raw -Encoding UTF8

            # Check if already modified
            if ($content -match "return crypto\.randomUUID\(\)" -or $content -match "// Cursor ID Modification Tool Injection") {
                Write-Host "[Skip] File already modified"
                $modifiedCount++
                continue
            }

            # Method 1: IOPlatformUUID modification
            if ($content -match "IOPlatformUUID") {
                Write-Host "[Found] Found IOPlatformUUID keyword"

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
                Write-Host "[Success] General injection method applied successfully"
                $modifiedCount++
            } else {
                Write-Host "[Warning] IOPlatformUUID not found, skipping file"
                continue
            }

            # Write modified content
            Set-Content -Path $file -Value $content -Encoding UTF8 -NoNewline
            Write-Host "[Completed] File modification completed: $(Split-Path $file -Leaf)"

        } catch {
            Write-Host "[Error] Failed to modify file: $($_.Exception.Message)"
            $fileName = Split-Path $file -Leaf
            $backupFile = "$backupPath\$fileName"
            if (Test-Path $backupFile) {
                Copy-Item $backupFile $file -Force
                Write-Host "[Restore] Restored file from backup"
            }
        }
    }

    if ($modifiedCount -gt 0) {
        Write-Host ""
        Write-Host "[Completed] Successfully modified $modifiedCount JS files"
        Write-Host "[Backup] Original files backed up at: $backupPath"
        Write-Host "[Info] JavaScript injection enabled for device identification bypass"
        return $true
    } else {
        Write-Host "[Failure] No files were successfully modified"
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
    Write-Host "[Error] Please run this script as an administrator"
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
Write-Host "================================="
Write-Host "Cursor Trial Pro Extension Tool"
Write-Host "================================="

# User confirmation
Write-Host ""
Write-Host "[Confirmation] Please confirm you want to execute the script"
$confirmation = Read-Host "Continue execution? (Enter y or yes to continue, any other key to exit)"
if ($confirmation -notmatch "^(y|yes)$") {
    Write-Host "[Exit] User canceled execution, exiting script"
    Read-Host "Press Enter to exit"
    exit 0
}
Write-Host "[Confirmation] User confirmed execution"
Write-Host ""

# Ensure backup directory exists
if (-not (Test-Path $BACKUP_DIR)) {
    try {
        New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
        Write-Host "[Backup Directory] Backup directory created: $BACKUP_DIR"
    } catch {
        Write-Host "[Warning] Failed to create backup directory: $($_.Exception.Message)"
    }
}

# Execute Modify Machine Code Only
Write-Host "[Start] Starting machine code modification..."

# Execute machine code modification
$configSuccess = Modify-MachineCodeConfig -Mode "MODIFY_ONLY"

if ($configSuccess) {
    Write-Host ""
    Write-Host "[Configuration] Machine code configuration modified successfully!"

    # Modify registry
    Write-Host "[Registry] Modifying system registry..."
    $registrySuccess = Update-MachineGuid

    # JavaScript injection
    Write-Host ""
    Write-Host "[Device ID Bypass] Executing JavaScript injection..."
    Write-Host "[Info] This modifies Cursor core JS files for deeper device identification bypass"
    $jsSuccess = Modify-CursorJSFiles

    if ($registrySuccess) {
        Write-Host "[Registry] System registry modified successfully"

        if ($jsSuccess) {
            Write-Host "[JavaScript Injection] JavaScript injection executed successfully"
            Write-Host ""
            Write-Host "[Completed] All machine code modifications completed!"
            Write-Host "[Details] Completed the following modifications:"
            Write-Host "  ✓ Cursor configuration (storage.json)"
            Write-Host "  ✓ System registry (MachineGuid)"
            Write-Host "  ✓ JavaScript core injection (device ID bypass)"
        } else {
            Write-Host "[Warning] JavaScript injection failed, but other modifications succeeded"
            Write-Host ""
            Write-Host "[Completed] Machine code modifications completed!"
            Write-Host "[Details] Completed the following modifications:"
            Write-Host "  ✓ Cursor configuration (storage.json)"
            Write-Host "  ✓ System registry (MachineGuid)"
            Write-Host "  ⚠ JavaScript core injection (partially failed)"
        }

        # Protect configuration file
        Write-Host "[Protection] Setting configuration file protection..."
        try {
            $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
            $configFile = Get-Item $configPath
            $configFile.IsReadOnly = $true
            Write-Host "[Protection] Configuration file set to read-only to prevent Cursor overwriting"
            Write-Host "[Tip] File path: $configPath"
        } catch {
            Write-Host "[Warning] Failed to set read-only attribute: $($_.Exception.Message)"
            Write-Host "[Suggestion] Manually right-click the file → Properties → Check 'Read-only'"
        }
    } else {
        Write-Host "[Warning] Registry modification failed, but configuration modified successfully"

        if ($jsSuccess) {
            Write-Host "[JavaScript Injection] JavaScript injection executed successfully"
            Write-Host ""
            Write-Host "[Partially Completed] Configuration and JavaScript injection completed, registry modification failed"
            Write-Host "[Suggestion] Administrator privileges may be required for registry modification"
            Write-Host "[Details] Completed the following modifications:"
            Write-Host "  ✓ Cursor configuration (storage.json)"
            Write-Host "  ⚠ System registry (MachineGuid) - Failed"
            Write-Host "  ✓ JavaScript core injection (device ID bypass)"
        } else {
            Write-Host "[Warning] JavaScript injection failed"
            Write-Host ""
            Write-Host "[Partially Completed] Configuration modified, registry and JavaScript injection failed"
            Write-Host "[Suggestion] Administrator privileges may be required for registry modification"
        }

        # Protect configuration file even if registry modification failed
        Write-Host "[Protection] Setting configuration file protection..."
        try {
            $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
            $configFile = Get-Item $configPath
            $configFile.IsReadOnly = $true
            Write-Host "[Protection] Configuration file set to read-only to prevent Cursor overwriting"
            Write-Host "[Tip] File path: $configPath"
        } catch {
            Write-Host "[Warning] Failed to set read-only attribute: $($_.Exception.Message)"
            Write-Host "[Suggestion] Manually right-click the file → Properties → Check 'Read-only'"
        }
    }

    Write-Host "[Tip] You can now start Cursor with the new machine code configuration"
} else {
    Write-Host ""
    Write-Host "[Failure] Machine code modification failed!"
    Write-Host "[Suggestion] Check error messages and retry"
}

# Script completion
Write-Host ""
Write-Host "[Script Completed] Thank you for using the Cursor Machine Code Modification Tool!"
Write-Host "[Tip] If you encounter issues, refer to documentation or retry the script"
Write-Host ""
Read-Host "Press Enter to exit"
exit 0
