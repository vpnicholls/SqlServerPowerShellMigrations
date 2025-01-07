<<<<<<< HEAD
<#
=======
﻿<#
>>>>>>> 42fbb9a (Initial commit of MigrateInstances.ps1)
    .SYNOPSIS
    Migrates SQL Server objects, user databases and updates user database settings.

    .DESCRIPTION
    This script:
    - migrates various instance-level objects
    - Migrates various server objects
    - migrates specified databases from a source SQL Server instance to target instance(s)
    - updates various database settings
    It uses dbatools for SQL operations, includes logging, credential validation, and ensures administrative privileges are present for execution.

    .PARAMETER myCredential
    The credentials used to connect to the SQL Server instances.

    .PARAMETER ScriptEventLogPath
    The directory where events should be logged for this script.

    .PARAMETER SourceInstance
    The name of the SQL Server from which databases are migrated.

    .PARAMETER TargetInstances
    An array of hashtables specifying target SQL Server instances, their instances, and roles.
    Possible roles are:
    - AGPrimary
    - AGSecondary
    - ReplicationPublisher
    - ReplicationDistributor
    - ReplicationSubscriber
    - LogShippingPrimary
    - LogShippingSecondary
    - Standalone

    .PARAMETER Environment
    Specifies the environment where the migration is occurring (Dev, QA, or Prod). This is reserved for future development. Mandatory set to $false until it is required.

    .PARAMETER NetworkBackupDir
    The network share path where database backups are stored for migration. Used when a network share is available for backup and restore operations.
    If LocalBackupDir is defined, then NetworkBackupDir is ignored and databases are created from backups stored in LocalBackupDir.

    .PARAMETER LocalBackupDir
    The local directory on each target host where manual database backups are placed if network share is not available. Backups must be named <DatabaseName>.bak

    .PARAMETER Databases
    An array of database names to be migrated.

    .PARAMETER AgentCredentials
    Credentials for SQL Server Agent jobs. This is reserved for future development.

    .PARAMETER ExcludedLogins
    An array of login names to exclude from migration. This is reserved for future development.

    .PARAMETER ExcludedOperators
    Operator names to exclude from migration. This is reserved for future development.

    .PARAMETER Categories
    Job categories to consider during the migration process. This is reserved for future development. Mandatory set to $false until it is required.

    .EXAMPLE
    $params = @{
        myCredential = $myCred
        ScriptEventLogPath = "$env:userprofile\Documents"
        SourceInstance = "SQL01"
        TargetInstances = @(
            @{Host="SQL02"; Instance="MSSQLSERVER"; Roles=@("AGPrimary", "ReplicationPublisher")},
            @{Host="SQL03"; Instance="MSSQLSERVER"; Roles=@("AGSecondary")},
            @{Host="SQL04"; Instance="MSSQLSERVER"; Roles=@("ReplicationDistributor", "ReplicationSubscriber")}
            @{Host="SQL05"; Instance="MSSQLSERVER"; Roles=@("Standalone")}
        )
        Environment = "QA"
        NetworkBackupDir = "\\backup\dir"
        LocalBackupDir = "C:\ManualBackups"
        Databases = @("DB1", "DB2")
        AgentCredentials = "agentCred"
        ExcludedLogins = @("login1", "login2")
        ExcludedOperators = "Op1"
        Categories = "Cat1"
    }
    .\MigrateInstances.ps1 @params

    .NOTES
    - This script does not handle the setup of Always On Availability Groups, replication, or log shipping, which must be done separately.
    - Ensure the dbatools module is installed before running this script.
    - The script will attempt to elevate privileges if not run as administrator.
    - If both NetworkBackupDir and LocalBackupDir are provided, LocalBackupDir takes precedence.

    .LINK
    https://github.com/vpnicholls/SqlServerPowerShellMigrations
#>

#requires -module dbatools

Set-StrictMode -Version Latest

param (
    [Parameter(Mandatory=$true)][PSCredential]$myCredential,
    [Parameter(Mandatory=$true)][string]$ScriptEventLogPath,
    [Parameter(Mandatory=$true)][string]$SourceInstance,
    [Parameter(Mandatory=$true)][array]$TargetInstances, # Array of hashtables for target instances
    [Parameter(Mandatory=$false)][ValidateSet("Dev", "QA", "Prod")][string]$Environment,
    [Parameter(Mandatory=$false)][string]$NetworkBackupDir,
    [Parameter(Mandatory=$false)][string]$LocalBackupDir,
    [Parameter(Mandatory=$true)][string[]]$Databases,
    [Parameter(Mandatory=$false)][string]$AgentCredentials,
    [Parameter(Mandatory=$false)][string[]]$ExcludedLogins,
    [Parameter(Mandatory=$false)][string]$ExcludedOperators,
    [Parameter(Mandatory=$false)][string]$Categories
)

# Generate log file name with datetime stamp
$logFileName = Join-Path -Path $ScriptEventLogPath -ChildPath "MigrateInstancesLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Define the function to write to the log file
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG", "VERBOSE", "FATAL")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$Level] $Message" | Out-File -FilePath $logFileName -Append
}

# Define the function to ensure script runs with admin privileges
function EnsureAdminPrivileges {
    [CmdletBinding()]
    param()
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log "Script requires admin privileges. Attempting to restart with elevated privileges." -Level "WARNING"
        $arguments = "& '" + $myinvocation.mycommand.definition + "'"
        Start-Process powershell -Verb runAs -ArgumentList $arguments
        exit
    }
}

# Function to validate credentials
function Test-Credential {
    param (
        [PSCredential]$Credential,
        [string]$Instance
    )
    try {
        $testConnection = Test-DbaConnection -SqlInstance $Instance -SqlCredential $Credential
        if (-not $testConnection.Connected) {
            throw "Connection to $Instance failed."
        }
    } catch {
        Write-Log -Message "Credential validation failed: $_" -Level "ERROR"
        return $false
    }
    return $true
}

# Function to migrate user databases
function Migrate-Databases {
    param (
        [string]$SourceInstance,
        [string]$DestinationInstance,
        [string[]]$Databases,
        [string]$NetworkBackupDir,
        [string]$LocalBackupDir,
        [PSCredential]$Credential
    )

    $CompletedCount = 0
    $DatabasesCount = $Databases.Count
    Write-Log -Message "Starting database migration process." -Level "INFO"
    
    if ($LocalBackupDir -and $NetworkBackupDir) {
        Write-Log -Message "Both LocalBackupDir and NetworkBackupDir are specified. Using LocalBackupDir for migration." -Level "INFO"
    }

    if ($LocalBackupDir -and (Test-Path -Path $LocalBackupDir)) {
        Write-Log -Message "Using local backup directory for database migration." -Level "INFO"
        
        # Log files that do not match any database in $Databases
        $allFiles = Get-ChildItem -Path $LocalBackupDir -Filter "*.bak"
        $mismatchedFiles = $allFiles | Where-Object { $_.BaseName -notin $Databases }
        foreach ($file in $mismatchedFiles) {
            Write-Log -Message "File '$($file.Name)' in $LocalBackupDir does not match any database in the list." -Level "WARNING"
        }

        foreach ($Database in $Databases) {
            Write-Log -Message "Starting manual restore of '$Database'." -Level "INFO"
            $CompletedCount++

            try {
                $backupFile = Join-Path -Path $LocalBackupDir -ChildPath "$Database.bak"
                if (Test-Path -Path $backupFile) {
                    try {
                        Restore-DbaDatabase -SqlInstance $DestinationInstance -Path $backupFile -DatabaseName $Database -SqlCredential $Credential -ErrorAction Stop
                        Write-Log -Message "Successfully restored database '$Database' from local backup. Completed migration for ($CompletedCount of $DatabasesCount) databases." -Level "SUCCESS"
                    }
                    catch [Microsoft.SqlServer.Management.Smo.FailedOperationException] {
                        if ($_.Exception.Message -like "*already exists*") {
                            Write-Log -Message "Database '$Database' already exists. Skipping restore." -Level "WARNING"
                        }
                        elseif ($_.Exception.Message -like "*access denied*") {
                            Write-Log -Message "Insufficient permissions to restore database '$Database'. Skipping." -Level "WARNING"
                        }
                        else {
                            Write-Log -Message "Failed to restore '$Database': $_" -Level "ERROR"
                        }
                    }
                    catch {
                        Write-Log -Message "Unexpected error restoring '$Database': $_" -Level "ERROR"
                    }
                } else {
                    Write-Log -Message "Backup file for '$Database' not found in $LocalBackupDir." -Level "ERROR"
                }
            }
            catch {
                Write-Log -Message "An error occurred while processing '$Database': $_" -Level "ERROR"
            }
        }
    } 
    elseif ($NetworkBackupDir) {
        if (-not (Test-Path -Path $NetworkBackupDir)) {
            throw "Network backup directory $NetworkBackupDir does not exist."
        }
        Write-Log -Message "Using network backup directory for database migration." -Level "INFO"
        foreach ($Database in $Databases) {
            Write-Log -Message "Starting migration of '$Database'." -Level "INFO"
            $CompletedCount++

            try {
                Copy-DbaDatabase -Source $SourceInstance -Destination $DestinationInstance -Database $Database -BackupRestore -SharedPath $NetworkBackupDir -SourceSqlCredential $Credential -DestinationSqlCredential $Credential
                Write-Log -Message "Successfully migrated database '$Database'. Completed migration for ($CompletedCount of $DatabasesCount) databases." -Level "SUCCESS"
            }
            catch {
                Write-Log -Message "Failed to migrate '$Database': $_" -Level "ERROR"
            }
        }
    }
    else {
        Write-Log -Message "No valid backup directory specified. Please specify either NetworkBackupDir or LocalBackupDir." -Level "ERROR"
    }
}

# Function to update database settings
function Update-DatabaseSettings {
    param (
        [string]$Instance,
        [string[]]$Databases,
        [PSCredential]$Credential
    )

    $CompletedCount = 0
    $DatabasesCount = $Databases.Count
    Write-Log -Message "Starting database settings update process." -Level "INFO"

    $queryPageVerify = "ALTER DATABASE [$Database] SET PAGE_VERIFY CHECKSUM;"
    $queryTargetRecovery = "ALTER DATABASE [$Database] SET TARGET_RECOVERY_TIME = 60 SECONDS;"

    foreach ($Database in $Databases) {
        Write-Log -Message "Starting settings updates for '$Database'. Completed updates for ($CompletedCount of $DatabasesCount) databases." -Level "INFO"
        $CompletedCount++

        try {
            Write-Log -Message "Setting database state to restricted user: $Database" -Level "INFO"
            Set-DbaDbState -SqlInstance $Instance -Database $Database -SqlCredential $Credential -RestrictedUser -Force

            Write-Log -Message "Setting database owner: $Database" -Level "INFO"
            Set-DbaDbOwner -SqlInstance $Instance -Database $Database -SqlCredential $Credential

            Write-Log -Message "Setting database comnpatibility level: $Database" -Level "INFO"
            Set-DbaDbCompatibility -SqlInstance $Instance -SqlCredential $Credential
            
            Write-Log -Message "Enabling and setting query store options: $Database" -Level "INFO"
            Set-DbaDbQueryStoreOption -SqlInstance $Instance -SqlCredential $Credential -State ReadWrite -MaxSize 128
            
            Write-Log -Message "Setting database page verify option: $Database" -Level "INFO"
            Invoke-DbaQuery -SqlInstance $Instance -Database $Database -SqlCredential $Credential -Query $queryPageVerify
            
            Write-Log -Message "Setting database target recovery time: $Database" -Level "INFO"
            Invoke-DbaQuery -SqlInstance $Instance -Database $Database -SqlCredential $Credential -Query $queryTargetRecovery
            
            Write-Log -Message "Reverting database state to multi user: $Database" -Level "INFO"
            Set-DbaDbState -SqlInstance $Instance -Database $Database -SqlCredential $Credential -MultiUser

            Write-Log -Message "Successfully updated settings for database '$Database'." -Level "SUCCESS"
        }
        catch {
            Write-Log -Message "Failed to update settings for '$Database': $_" -Level "ERROR"
        }
        finally {
            Set-DbaDbState -SqlInstance $Instance -Database $Database -SqlCredential $Credential -MultiUser
        }
    }
}

# Main script execution
EnsureAdminPrivileges

# Validate credentials for all instances
foreach ($Target in $TargetInstances) {
    $Instance = "$($Target.Host)\$($Target.Instance)"
    if (-not (Test-Credential -Credential $myCredential -Instance $Instance)) {
        Write-Log -Message "Script terminated due to invalid credentials for $Instance." -Level "FATAL"
        exit
    }
}

# Migrate and Update databases on all primary instances
$primaryInstances = $TargetInstances | Where-Object { $_.Roles -in @("AGPrimary", "LogShippingPrimary", "Standalone") }

foreach ($primaryInstance in $primaryInstances) {
    $PrimaryInstanceName = "$($primaryInstance.Host)\$($primaryInstance.Instance)"
    Write-Log -Message "Starting database migration to $PrimaryInstanceName." -Level "INFO"
    Migrate-Databases -SourceInstance $SourceInstance -DestinationInstance $PrimaryInstanceName -Databases $Databases -NetworkBackupDir $NetworkBackupDir -LocalBackupDir $LocalBackupDir -Credential $myCredential
    Update-DatabaseSettings -Instance $PrimaryInstanceName -Databases $Databases -Credential $myCredential
}

if ($primaryInstances.Count -eq 0) {
    Write-Log -Message "No primary instances (AGPrimary, LogShippingPrimary, or Standalone) found among target instances." -Level "ERROR"
}

<<<<<<< HEAD
Write-Log -Message "Migration process completed." -Level "SUCCESS"
=======
Write-Log -Message "Migration process completed." -Level "SUCCESS"
>>>>>>> 42fbb9a (Initial commit of MigrateInstances.ps1)
