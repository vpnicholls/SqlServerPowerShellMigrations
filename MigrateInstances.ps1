<#
    .SYNOPSIS
    Migrates SQL Server objects, user databases and updates user database settings.

    .DESCRIPTION
    This script:
    - migrates various instance-level objects
    - migrates logins and adds them to the applicable "server-level roles"
    - migrates Agent credentials
    - migrates Agent proxies (to be developed)
    - migrates Agent operators (to be developed)
    - migrates Database Mail
    - migrates linked servers (to be developed)
    - migrates SQL Agent jobs (to be developed)
    - migrates SQL Agent alerts(to be developed)
    - migrates sys.configurations (to be developed)
    - migrates server triggers (to be developed)
    - migrates endpoints (to be developed)
    - migrates Extended Events sessions (to be developed)
    - migrates certificates, asymmetric keys, and symmetric keys for encryption
    - migrates Server Audits and Audit Specifications (to be developed)
    - migrates Resource Governor configirations (to be developed)

    - migrates specified databases from a source SQL Server instance to target instance(s)
    - updates various database settings
    
    It uses dbatools for SQL operations, includes logging, credential validation, and ensures administrative privileges are present for execution.

    The general approach is to skip any objects that already exist on the target. Database settings, though, will be updated, even if the database already exists.
    This is to ensure that database settings adhere to the desired standards and consistency. As always, test in a suitable non-Production environment.

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

    .PARAMETER LoginType
    An optional parameter if you are migrating either SQL logins or Windows logins. Not required if you are migrating both types of logins.

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
            @{HostServer="SQL02"; Instance="MSSQLSERVER"; Roles=@("AGPrimary", "ReplicationPublisher")},
            @{HostServer="SQL03"; Instance="MSSQLSERVER"; Roles=@("AGSecondary")},
            @{HostServer="SQL04"; Instance="MSSQLSERVER"; Roles=@("ReplicationDistributor", "ReplicationSubscriber")}
            @{HostServer="SQL05"; Instance="MSSQLSERVER"; Roles=@("Standalone")}
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
    - Author: Vaughan Nicholls
    - This script does not handle the setup of Always On Availability Groups, replication, or log shipping, which must be done separately.
    - Ensure the dbatools module is installed before running this script.
    - The script will attempt to elevate privileges if not run as administrator.
    - If both NetworkBackupDir and LocalBackupDir are provided, LocalBackupDir takes precedence.

    .LINK
    https://github.com/vpnicholls/SqlServerPowerShellMigrations
#>

#requires -module dbatools

# Set-StrictMode -Version Latest

param (
    [Parameter(Mandatory=$true)][PSCredential]$myCredential,
    [Parameter(Mandatory=$true)][string]$ScriptEventLogPath,
    [Parameter(Mandatory=$true)][string]$SourceInstance,
    [Parameter(Mandatory=$true)][array]$TargetInstances, # Array of hashtables for target instances
    [Parameter(Mandatory=$false)][ValidateSet("Dev", "QA", "Prod")][string]$Environment,
    [Parameter(Mandatory=$false)][string]$NetworkBackupDir,
    [Parameter(Mandatory=$false)][string]$LocalBackupDir,
    [Parameter(Mandatory=$true)][string[]]$Databases,
    [Parameter(Mandatory=$false)][string[]]$AgentCredentials,
    [Parameter(Mandatory=$false)][string[]]$ExcludedLogins,
    [Parameter(Mandatory=$false)][ValidateSet("SQL", "Windows")][string]$LoginType,
    [Parameter(Mandatory=$false)][string[]]$ExcludedOperators,
    [Parameter(Mandatory=$false)][string[]]$Categories
)

# Generate log file name with datetime stamp
$logFileName = Join-Path -Path $ScriptEventLogPath -ChildPath "MigrateInstancesLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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

# Function to test connectivity using Connect-DbaInstance
function Test-Connectivity {
    param (
        [string]$ServerHost,
        [string]$InstanceName,
        [PSCredential]$Credential
    )
    try {
        Write-Verbose "Testing connectivity to $ServerHost..."
        
        # Construct the SqlInstance string
        $SqlInstance = if ($InstanceName -eq "MSSQLSERVER") { $ServerHost } else { "$ServerHost\$InstanceName" }
        
        # Try to connect
        $connection = Connect-DbaInstance -SqlInstance $SqlInstance -SqlCredential $Credential -ErrorAction Stop
        
        # If connection is successful, return true
        if ($connection) {
            Write-Verbose "Successfully connected to $SqlInstance."
            return $true
        }
        else {
            Write-Log -Message "Failed to connect to $SqlInstance." -Level "ERROR"
            return $false
        }
    }
    catch {
        # Log any errors encountered
        Write-Log -Message "Error connecting to $($SqlInstance): $_" -Level "ERROR"
        return $false
    }
    finally {
        # Ensure any open connections are closed
        if ($connection) {
            Disconnect-DbaInstance -InputObject $connection
        }
    }
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
    
    $successfulRestores = 0
    $failedRestores = 0
    $skippedDatabases = 0
    $missingBackups = 0

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
            Write-Log -Message "Checking if database '$Database' exists before restore." -Level "INFO"
            $CompletedCount++

            try {
                $backupFile = Join-Path -Path $LocalBackupDir -ChildPath "$Database.bak"
                if (Test-Path -Path $backupFile) {
                    # Check if the database already exists
                    $existingDatabase = Get-DbaDatabase -SqlInstance $DestinationInstance -Database $Database -ErrorAction SilentlyContinue
                    if ($existingDatabase) {
                        Write-Log -Message "Database '$Database' already exists on $DestinationInstance. Skipping restore." -Level "WARNING"
                        $skippedDatabases++
                    } else {
                        try {
                            Write-Log -Message "Starting restore of '$Database' from '$LocalBackupDir'." -Level "INFO"
                            $restoreResult = Restore-DbaDatabase -SqlInstance $DestinationInstance -Path $backupFile -DatabaseName $Database -SqlCredential $Credential -ErrorAction Stop -EnableException
                            $null = $restoreResult  # This line ensures the output is not shown but the result is still accessible

                            # Check the RestoreComplete property
                            if ($restoreResult.RestoreComplete) {
                                Write-Log -Message "Successfully restored database '$Database' from local backup. Completed migration for ($CompletedCount of $DatabasesCount) databases." -Level "SUCCESS"
                                $successfulRestores++
                            } else {
                                Write-Log -Message "Restore of database '$Database' did not complete successfully." -Level "ERROR"
                                $failedRestores++
                            }
                        }
                        catch [Microsoft.SqlServer.Management.Smo.FailedOperationException] {
                            if ($_.Exception.Message -like "*access denied*") {
                                Write-Log -Message "Insufficient permissions to restore database '$Database'. Skipping." -Level "WARNING"
                                $failedRestores++
                            }
                            else {
                                Write-Log -Message "Failed to restore '$Database': $_" -Level "ERROR"
                                $failedRestores++
                            }
                        }
                        catch {
                            Write-Log -Message "Unexpected error restoring '$Database': $_" -Level "ERROR"
                            $failedRestores++
                        }
                    }
                } else {
                    Write-Log -Message "Backup file for '$Database' not found in $LocalBackupDir." -Level "ERROR"
                    $missingBackups++
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
            Write-Log -Message "Checking if database '$Database' exists before migration." -Level "INFO"
            $CompletedCount++

            # Since Copy-DbaDatabase handles existence check internally, we'll only log the intent
            $existingDatabase = Get-DbaDatabase -SqlInstance $DestinationInstance -Database $Database -ErrorAction SilentlyContinue
            if ($existingDatabase) {
                Write-Log -Message "Database '$Database' already exists on $DestinationInstance. Skipping migration." -Level "WARNING"
                $skippedDatabases++
            } else {
                try {
                    Write-Log -Message "Starting migration of '$Database'." -Level "INFO"
                    $migrationResult = Copy-DbaDatabase -Source $SourceInstance -Destination $DestinationInstance -Database $Database -BackupRestore -SharedPath $NetworkBackupDir -SourceSqlCredential $Credential -DestinationSqlCredential $Credential -EnableException -WarningAction SilentlyContinue -ErrorAction Stop
                    Write-Log -Message "Successfully migrated database '$Database'. Completed migration for ($CompletedCount of $DatabasesCount) databases." -Level "SUCCESS"
                    $successfulRestores++
                }
                catch {
                    Write-Log -Message "Failed to migrate '$Database': $_" -Level "ERROR"
                    $failedRestores++
                }
            }
        }
    }
    else {
        Write-Log -Message "No valid backup directory specified. Please specify either NetworkBackupDir or LocalBackupDir." -Level "ERROR"
    }

    # Summary Log
    Write-Log -Message "There were $DatabasesCount requested to be migrated." -Level "INFO"
    Write-Log -Message "There were $missingBackups databases where an associated backup could not be found." -Level "INFO"
    Write-Log -Message "There were $skippedDatabases databases skipped as they already exist on the target." -Level "INFO"
    Write-Log -Message "There were $failedRestores databases where a restore was attempted but failed." -Level "INFO"
    Write-Log -Message "There were $successfulRestores databases with successful restores." -Level "INFO"
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

    foreach ($Database in $Databases) {
        Write-Log -Message "Starting settings updates for '$Database'. Completed updates for ($CompletedCount of $DatabasesCount) databases." -Level "INFO"
        $CompletedCount++

        $queryPageVerify = "ALTER DATABASE [$Database] SET PAGE_VERIFY CHECKSUM;"
        $queryTargetRecovery = "ALTER DATABASE [$Database] SET TARGET_RECOVERY_TIME = 60 SECONDS;"

        try {
            Write-Log -Message "Setting database state to Restricted User mode: $Database" -Level "INFO"
            try {
                Set-DbaDbState -SqlInstance $Instance -Database $Database -SqlCredential $Credential -RestrictedUser -Force -EnableException | Out-Null
            }
            catch {
                Write-Log -Message "Failed to set database state for '$Database' to Restricted User mode: $_" -Level "ERROR"
            }

            Write-Log -Message "Setting database owner: $Database" -Level "INFO"
            try {
                Set-DbaDbOwner -SqlInstance $Instance -Database $Database -SqlCredential $Credential -EnableException | Out-Null
            }
            catch {
                Write-Log -Message "Failed to set database owner for '$Database': $_" -Level "ERROR"
            }

            Write-Log -Message "Setting database compatibility level: $Database" -Level "INFO"
            try {
                Set-DbaDbCompatibility -SqlInstance $Instance -SqlCredential $Credential -Database $Database -EnableException | Out-Null
            }
            catch {
                Write-Log -Message "Failed to set database compatibility level for '$Database': $_" -Level "ERROR"
            }

            Write-Log -Message "Enabling and setting query store options: $Database" -Level "INFO"
            try {
                Set-DbaDbQueryStoreOption -SqlInstance $Instance -SqlCredential $Credential -Database $Database -State ReadWrite -MaxSize 128 -EnableException | Out-Null
            }
            catch {
                Write-Log -Message "Failed to set query store options for '$Database': $_" -Level "ERROR"
            }

            Write-Log -Message "Setting database page verify option: $Database" -Level "INFO"
            try {
                Invoke-DbaQuery -SqlInstance $Instance -Database $Database -SqlCredential $Credential -Query $queryPageVerify -EnableException | Out-Null
            }
            catch {
                Write-Log -Message "Failed to set page verify option for '$Database': $_" -Level "ERROR"
            }

            Write-Log -Message "Setting database target recovery time: $Database" -Level "INFO"
            try {
                Invoke-DbaQuery -SqlInstance $Instance -Database $Database -SqlCredential $Credential -Query $queryTargetRecovery -EnableException | Out-Null
            }
            catch {
                Write-Log -Message "Failed to set target recovery time for '$Database': $_" -Level "ERROR"
            }

            Write-Log -Message "Reverting database state to Multi User mode: $Database" -Level "INFO"
            try {
                Set-DbaDbState -SqlInstance $Instance -Database $Database -SqlCredential $Credential -MultiUser -EnableException | Out-Null
            }
            catch {
                Write-Log -Message "Failed to revert database state to Multi User for '$Database': $_" -Level "ERROR"
            }

            Write-Log -Message "Successfully updated settings for database '$Database'." -Level "SUCCESS"
        }
        catch {
            Write-Log -Message "A general error occurred while updating settings for '$Database': $_" -Level "ERROR"
        }
        finally {
            Write-Log -Message "Ensuring database state is set to Multi User for '$Database'" -Level "INFO"
            try {
                Set-DbaDbState -SqlInstance $Instance -Database $Database -SqlCredential $Credential -MultiUser -EnableException | Out-Null
            }
            catch {
                Write-Log -Message "Failed to ensure database state is Multi User for '$Database': $_" -Level "ERROR"
            }
        }
    }
}

function Migrate-Logins {
    param (
        [string]$SourceInstance,
        [string]$DestinationInstance,
        [string]$LoginType = "",
        [string[]]$ExcludedLogins,
        [PSCredential]$Credential
    )
    try {
        # Common system logins to exclude
        $systemLogins = @(
            "sa",
            "##MS_PolicyEventProcessingLogin##",
            "##MS_PolicyTsqlExecutionLogin##",
            "NT AUTHORITY\SYSTEM",
            "NT Service\MSSQLSERVER",
            "NT SERVICE\SQLSERVERAGENT",
            "NT SERVICE\SQLTELEMETRY",
            "NT SERVICE\SQLWriter",
            "NT SERVICE\Winmgmt"
        )
        
        $combinedExcludedLogins = $ExcludedLogins + $systemLogins

        # Determine which logins to migrate based on $LoginType
        if ($LoginType -eq "SQL") {
            $Logins = Get-DbaLogin -SqlInstance $SourceInstance -SqlCredential $Credential -Type SQL -ExcludeLogin $combinedExcludedLogins
        }
        elseif ($LoginType -eq "Windows") {
            $Logins = Get-DbaLogin -SqlInstance $SourceInstance -SqlCredential $Credential -Type Windows -ExcludeLogin $combinedExcludedLogins
        }
        else {
            # If no specific LoginType is provided or if it's not recognized, migrate both SQL and Windows logins
            $Logins = Get-DbaLogin -SqlInstance $SourceInstance -SqlCredential $Credential -ExcludeLogin $combinedExcludedLogins
        }

        Write-Log -Message "Migrating $($Logins.Count) logins from $SourceInstance to $DestinationInstance." -Level "INFO"

        $skippedLogins = 0
        $failedLogins = 0
        $successfulLogins = 0

        # Migrate the logins to the destination instance
        $migratedLogins = $Logins | ForEach-Object {
            $loginName = $_.Name
            # Check if the login already exists on the destination
            $existingLogin = Get-DbaLogin -SqlInstance $DestinationInstance -SqlCredential $Credential -Login $loginName -ErrorAction SilentlyContinue

            if ($existingLogin) {
                Write-Log -Message "Login '$loginName' already exists on $DestinationInstance. Skipping creation." -Level "WARNING"
                $skippedLogins++
                # Return an object to mimic the structure of Copy-DbaLogin's output for consistency
                [PSCustomObject]@{
                    Name = $loginName
                    Status = 'Skipped'
                    Error = 'Login already exists'
                }
            } else {
                try {
                    $result = Copy-DbaLogin -Source $SourceInstance -Destination $DestinationInstance -Login $loginName -SourceSqlCredential $Credential -DestinationSqlCredential $Credential -EnableException -WarningAction SilentlyContinue -ErrorAction Stop
                    if ($result.Status -eq 'Successful') {
                        $successfulLogins++
                    } else {
                        $failedLogins++
                        Write-Log -Message "Failed to migrate login: $($_.Name) - Error: $($result.Error)" -Level "ERROR"
                    }
                }
                catch {
                    $failedLogins++
                    Write-Log -Message "Failed to migrate login: $loginName - Error: $_" -Level "ERROR"
                }
            }
        }

        # Log the results
        $migratedLogins | ForEach-Object {
            if ($_.Status -eq 'Successful') {
                Write-Log -Message "Successfully migrated login: $($_.Name)" -Level "SUCCESS"
            } elseif ($_.Status -eq 'Skipped') {
                Write-Log -Message "Login migration skipped: $($_.Name) - Reason: $($_.Error)" -Level "INFO"
            } else {
                Write-Log -Message "Failed to migrate login: $($_.Name) - Error: $($_.Error)" -Level "ERROR"
            }
        }

        # Summary Log
        Write-Log -Message "There were $skippedLogins logins that were skipped as they already exist on the target." -Level "INFO"
        Write-Log -Message "There were $failedLogins logins that were not migrated as the attempts failed." -Level "INFO"
        Write-Log -Message "There were $successfulLogins logins that were migrated successfully." -Level "INFO"
    }
    catch {
        Write-Log -Message "An error occurred while migrating logins: $_" -Level "ERROR"
    }
}

# Define the function to add migrated logins to the same server roles on the target as on the source
function Add-LoginsToRoles {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SourceInstance,
        [Parameter(Mandatory=$true)]
        [string]$DestinationInstance,
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        [Parameter(Mandatory=$false)]
        [string[]]$ExcludedLogins = @()
    )

    try {
        Write-Log -Message "Starting role assignment for logins from $SourceInstance to $DestinationInstance." -Level "INFO"

        # Counters for summary
        $skippedRoles = 0
        $failedRoles = 0
        $successfulRoles = 0

        # Retrieve logins from source instance, excluding specified logins
        $SourceLogins = Get-DbaLogin -SqlInstance $SourceInstance -SqlCredential $Credential -ExcludeLogin $ExcludedLogins

        foreach ($login in $SourceLogins) {
            $loginName = $login.Name
            Write-Log -Message "Processing login: $loginName" -Level "INFO"

            # Check if the login exists on the destination
            $destinationLogin = Get-DbaLogin -SqlInstance $DestinationInstance -SqlCredential $Credential -Login $loginName -ErrorAction SilentlyContinue

            if ($destinationLogin) {
                try {
                    $sourceRoles = $login.EnumRoles() | Where-Object { $_ -ne 'public' } # Exclude public role as it's default

                    if ($sourceRoles.Count -gt 0) {
                        Write-Log -Message "Login $loginName has roles on source: $([string]::Join(", ", $sourceRoles))" -Level "INFO"
                        
                        # Attempt to add each role
                        foreach ($role in $sourceRoles) {
                            $destinationRole = Get-DbaRole -SqlInstance $DestinationInstance -SqlCredential $Credential -Role $role -ErrorAction SilentlyContinue
                            if ($destinationRole) {
                                try {
                                    Add-DbaRoleMember -SqlInstance $DestinationInstance -SqlCredential $Credential -Role $role -Member $loginName -EnableException
                                    Write-Log -Message "Successfully added $loginName to role $role." -Level "SUCCESS"
                                    $successfulRoles++
                                }
                                catch {
                                    Write-Log -Message "Failed to add $loginName to role $($role): $_" -Level "ERROR"
                                    $failedRoles++
                                }
                            }
                            else {
                                Write-Log -Message "Role $role does not exist on $DestinationInstance. Skipping for login $loginName." -Level "WARNING"
                                $skippedRoles++
                            }
                        }
                    }
                    else {
                        Write-Log -Message "Login $loginName has no specific roles on $SourceInstance." -Level "INFO"
                    }
                }
                catch {
                    Write-Log -Message "Failed to enumerate roles for login $loginName: $_" -Level "ERROR"
                }
            }
            else {
                Write-Log -Message "Login $loginName does not exist on $DestinationInstance. Skipping role assignment." -Level "WARNING"
                # Here, we're not incrementing counters because this isn't about roles at this level, but you might want to consider adding a counter for skipped logins if needed
            }
        }

        # Summary Log
        Write-Log -Message "There were $skippedRoles roles that were skipped as they do not exist on the target." -Level "INFO"
        Write-Log -Message "There were $failedRoles roles where the assignment attempt failed." -Level "INFO"
        Write-Log -Message "There were $successfulRoles roles successfully assigned." -Level "INFO"
    }
    catch {
        Write-Log -Message "An error occurred while assigning roles to logins: $_" -Level "ERROR"
    }
}

# Function to migrate credentials
function Migrate-Credentials {
    param (
        [string]$SourceInstance,
        [array]$TargetInstances,
        [string]$AgentCredentials,
        [PSCredential]$Credential
    )
    try {
        # Retrieve the credential from the source instance
        $sourceCredential = Get-DbaCredential -SqlInstance $SourceInstance -Name $AgentCredentials -SqlCredential $Credential -ErrorAction Stop

        if ($sourceCredential) {
            Write-Log -Message "Found credential '$AgentCredentials' on source instance $SourceInstance. Proceeding with migration." -Level "INFO"

            # Loop through each target instance
            foreach ($Target in $TargetInstances) {
                $TargetInstanceName = if ($Target.Instance -eq "MSSQLSERVER") { $Target.HostServer } else { "$($Target.HostServer)\$($Target.Instance)" }

                try {
                    # Check if the credential already exists on the target
                    $existingCredential = Get-DbaCredential -SqlInstance $TargetInstanceName -Name $AgentCredentials -SqlCredential $Credential -ErrorAction SilentlyContinue

                    if ($existingCredential) {
                        Write-Log -Message "Credential '$AgentCredentials' already exists on $TargetInstanceName. Skipping creation." -Level "WARNING"
                    } else {
                        # Migrate the credential
                        $result = Copy-DbaCredential -Source $SourceInstance -Destination $TargetInstanceName -Name $AgentCredentials -SourceSqlCredential $Credential -DestinationSqlCredential $Credential -EnableException -WarningAction SilentlyContinue

                        if ($result.Status -eq 'Successful') {
                            Write-Log -Message "Successfully migrated credential '$AgentCredentials' to $TargetInstanceName." -Level "SUCCESS"
                        } else {
                            Write-Log -Message "Failed to migrate credential '$AgentCredentials' to $($TargetInstanceName): $($result.Error)" -Level "ERROR"
                        }
                    }
                }
                catch {
                    Write-Log -Message "An error occurred while migrating credential '$AgentCredentials' to $($TargetInstanceName): $_" -Level "ERROR"
                }
            }
        } else {
            Write-Log -Message "Credential '$AgentCredentials' not found on source instance $SourceInstance. No migration performed." -Level "WARNING"
        }
    }
    catch {
        Write-Log -Message "An error occurred while retrieving credential from source: $_" -Level "ERROR"
    }
}

# Define function to check Database Mail pre-requisites and enable them if not currently enabled
function Ensure-DatabaseMailPrerequisites {
    param (
        [Parameter(Mandatory=$true)]
        [array]$TargetInstances,
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential
    )

    foreach ($Target in $TargetInstances) {
        $TargetInstanceName = if ($Target.Instance -eq "MSSQLSERVER") { $Target.HostServer } else { "$($Target.HostServer)\$($Target.Instance)" }
        
        # Check if Database Mail is enabled
        $mailConfig = Get-DbaDbMail -SqlInstance $TargetInstanceName -SqlCredential $Credential -EnableException | Out-Null
        if (-not $mailConfig) {
            Write-Log -Message "Database Mail is not configured on $($TargetInstanceName). Enabling Database Mail..." -Level "INFO"
            try {
                # Use T-SQL to enable Database Mail
                $tSql = @"
                USE msdb;
                EXECUTE msdb.dbo.sp_configure 'show advanced options', 1;
                RECONFIGURE;
                EXECUTE msdb.dbo.sp_configure 'Database Mail XPs', 1;
                RECONFIGURE;
"@
                Invoke-DbaQuery -SqlInstance $TargetInstanceName -SqlCredential $Credential -Query $tSql -EnableException | Out-Null
                Write-Log -Message "Database Mail enabled on $($TargetInstanceName)." -Level "SUCCESS"
            }
            catch {
                Write-Log -Message "Failed to enable Database Mail on $($TargetInstanceName): $_" -Level "ERROR"
            }
        } else {
            Write-Log -Message "Database Mail is already configured on $($TargetInstanceName)." -Level "INFO"
        }
        
        # Check if Service Broker is enabled for msdb
        $dbBrokerStatus = Get-DbaDbServiceBrokerService -SqlInstance $TargetInstanceName -Database msdb -SqlCredential $Credential -EnableException | Out-Null
        if (-not $dbBrokerStatus.IsBrokerEnabled) {
            Write-Log -Message "Service Broker is not enabled for msdb on $($TargetInstanceName). Enabling Service Broker..." -Level "INFO"
            try {
                # Use T-SQL to enable Service Broker
                Invoke-DbaQuery -SqlInstance $TargetInstanceName -SqlCredential $Credential -Database master -Query "ALTER DATABASE msdb SET ENABLE_BROKER WITH ROLLBACK IMMEDIATE;" -EnableException | Out-Null
                Write-Log -Message "Service Broker enabled for msdb on $($TargetInstanceName)." -Level "SUCCESS"
            }
            catch {
                Write-Log -Message "Failed to enable Service Broker for msdb on $($TargetInstanceName): $_" -Level "ERROR"
            }
        } else {
            Write-Log -Message "Service Broker is already enabled for msdb on $($TargetInstanceName)." -Level "INFO"
        }
    }
}

# Define the function to migrate Database Mail configurations
function Migrate-DatabaseMail {
    param (
        [string]$SourceInstance,
        [array]$TargetInstances,
        [PSCredential]$Credential
    )
    try {
        # Retrieve Database Mail configurations from the source instance
        $dbMailConfigs = Get-DbaDbMail -SqlInstance $SourceInstance -SqlCredential $Credential -EnableException

        if ($dbMailConfigs) {
            foreach ($Target in $TargetInstances) {
                $TargetInstanceName = if ($Target.Instance -eq "MSSQLSERVER") { $Target.HostServer } else { "$($Target.HostServer)\$($Target.Instance)" }

                try {
                    # Check if Database Mail is already configured on the target
                    $existingDbMail = Get-DbaDbMail -SqlInstance $TargetInstanceName -SqlCredential $Credential -EnableException | Out-Null

                    if ($existingDbMail) {
                        Write-Log -Message "Database Mail is already configured on $TargetInstanceName. Skipping migration." -Level "WARNING"
                    } else {
                        Write-Log -Message "Found Database Mail configurations on source instance $SourceInstance. Proceeding with migration to $TargetInstanceName." -Level "INFO"
                        # Migrate Database Mail to the target instance
                        $migrationResult = Copy-DbaDbMail -Source $SourceInstance -Destination $TargetInstanceName -SourceSqlCredential $Credential -DestinationSqlCredential $Credential -EnableException | Out-Null

                        if ($migrationResult) {
                            Write-Log -Message "Successfully migrated Database Mail configurations to $TargetInstanceName." -Level "SUCCESS"
                        } else {
                            Write-Log -Message "Failed to migrate Database Mail configurations to $TargetInstanceName." -Level "ERROR"
                        }
                    }
                }
                catch {
                    Write-Log -Message "An error occurred while migrating Database Mail to $($TargetInstanceName): $_" -Level "ERROR"
                }
            }
        } else {
            Write-Log -Message "No Database Mail configurations found on source instance $SourceInstance. No migration performed." -Level "WARNING"
        }
    }
    catch {
        Write-Log -Message "An error occurred while retrieving Database Mail configurations from source: $_" -Level "ERROR"
    }
}

# Main script execution
EnsureAdminPrivileges

# Validate connectivity and credentials for all instances
foreach ($Target in $TargetInstances) {
    if (-not (Test-Connectivity -ServerHost $Target.HostServer -InstanceName $Target.Instance -Credential $myCredential)) {
        Write-Log -Message "Script terminated due to connectivity or credential issues for $($Target.HostServer)\$($Target.Instance)." -Level "FATAL"
        exit
    }
}

# Migrate and update databases on all primary instances
$primaryInstances = $TargetInstances | Where-Object { 
    $_.Roles -contains 'AGPrimary' -or 
    $_.Roles -contains 'LogShippingPrimary' -or 
    $_.Roles -contains 'Standalone'
}

if ($primaryInstances.Count -eq 0) {
    Write-Log -Message "No primary instances (AGPrimary, LogShippingPrimary, or Standalone) found among target instances." -Level "ERROR"
} else {
    foreach ($primaryInstance in $primaryInstances) {
        $PrimaryInstanceName = if ($primaryInstance.Instance -eq "MSSQLSERVER") {
            $primaryInstance.HostServer
        } else {
            "$($primaryInstance.HostServer)\$($primaryInstance.Instance)"
        }
        Write-Log -Message "Starting database migration to $PrimaryInstanceName." -Level "INFO"
        Migrate-Databases -SourceInstance $SourceInstance -DestinationInstance $PrimaryInstanceName -Databases $Databases -NetworkBackupDir $NetworkBackupDir -LocalBackupDir $LocalBackupDir -Credential $myCredential
        Update-DatabaseSettings -Instance $PrimaryInstanceName -Databases $Databases -Credential $myCredential
        Migrate-Logins -SourceInstance $SourceInstance -DestinationInstance $PrimaryInstanceName -LoginType $LoginType -ExcludedLogins $ExcludedLogins -Credential $myCredential
        Add-LoginsToRoles -SourceInstance $SourceInstance -DestinationInstance $PrimaryInstanceName -Credential $myCredential -ExcludedLogins $ExcludedLogins
        Migrate-Credentials -SourceInstance $SourceInstance -TargetInstances $TargetInstances -AgentCredentials $AgentCredentials -Credential $myCredential
        Ensure-DatabaseMailPrerequisites -TargetInstances $TargetInstances -Credential $myCredential
        Migrate-DatabaseMail -SourceInstance $SourceInstance -TargetInstances $TargetInstances -Credential $myCredential
    }
}

if ($primaryInstances.Count -eq 0) {
    Write-Log -Message "No primary instances (AGPrimary, LogShippingPrimary, or Standalone) found among target instances." -Level "ERROR"
}

Write-Log -Message "Migration process completed." -Level "SUCCESS"