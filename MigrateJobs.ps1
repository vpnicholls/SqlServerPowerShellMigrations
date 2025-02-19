<#
.SYNOPSIS
    Migrates SQL Agent jobs from instance to another.

.DESCRIPTION
    This script provides functions to manage the migration of SQL Agent jobs from one instance to another.
    It has been developed for the scenario where a migration is from a standalone instance to an Always On
    Primary Replica. It has functionality to insert a job step to check whether the replica is primary 
    before proceeding with the remainder of the job.
     
    It includes operations for:
    
    - Importing SQL Server credentials from a file on disk
    - Validating the various required directories
    - Creating a log writer
    - Migrating the job with an added step, leaving the job disabled on the target instance.

.PARAMETER SourceServer
    The source SQL Server instance where the jobs are being migrated from.

.PARAMETER TargetServer
    The target SQL Server instance where the jobs are being migrated to.

.PARAMETER JobDatabaseMapping
    A hashtable required to insert the applicable database name into the new job step.

.EXAMPLE
    .\MigrateJobs.ps1 -SourceServer "ServerA" -TargetServer "ServerB" -JobDatabaseMapping @{ "JobName1" = "Database1"; "JobName2" = "Database2" }
#>

param (
    [Parameter(Mandatory=$true)][string]$SourceServer,
    [Parameter(Mandatory=$true)][string]$TargetServer,
    [Parameter(Mandatory=$true)][hashtable]$JobDatabaseMapping,
    [System.Management.Automation.PSCredential]$SourceCredentials,
    [System.Management.Automation.PSCredential]$TargetCredentials,
    [string]$credentialsPath,
    [string]$ScriptEventLogPath = "$($PSScriptRoot)\Logs"
)

# Import dbatools module
Import-Module dbatools

# Set the path for the credentials file
$credentialsPath = "$( $PSScriptRoot )\Credentials\myCredentials.xml"

# Check for the SQL credentials file and assign these to the variables
if (-not (Test-Path -Path $credentialsPath)) {
    Write-Log -Message "Credentials file not found at $( $credentialsPath )." -Level "ERROR"
    throw "Credentials file does not exist."
}
$SourceCredentials = Import-Clixml -Path $credentialsPath
$TargetCredentials = Import-Clixml -Path $credentialsPath

# Create necessary directory if it doesn't exist
if (-not (Test-Path -Path $ScriptEventLogPath)) {
    New-Item -Path $ScriptEventLogPath -ItemType Directory
}

# Generate log file name with datetime stamp
$logFileName = Join-Path -Path $ScriptEventLogPath -ChildPath "FailoverLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Define the function to write to the log file and console
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG", "VERBOSE", "FATAL")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$( $timestamp ) [$( $Level )] $( $Message )"

    # Write to log file
    $logMessage | Out-File -FilePath $logFileName -Append
}

# Function to migrate and modify SQL Agent jobs
function Migrate-SQLAgentJobs {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SourceServer,
        [Parameter(Mandatory=$true)]
        [string]$TargetServer,
        [Parameter(Mandatory=$true)]
        [hashtable]$JobDatabaseMapping,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$SourceCredentials,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$TargetCredentials
    )

    $jobs = Get-DbaAgentJob -SqlInstance $SourceServer -SqlCredential $SourceCredentials

    foreach ($job in $jobs) {
        $jobName = $job.Name
        if ($JobDatabaseMapping.ContainsKey($jobName)) {
            $DatabaseName = $JobDatabaseMapping[$jobName]

            # Copy job to target server
            $copyResult = Copy-DbaAgentJob -Source $SourceServer -Destination $TargetServer -Job $jobName -SourceSqlCredential $SourceCredentials -DestinationSqlCredential $TargetCredentials

            if ($copyResult) {
                Write-Log -Message "Job $( $jobName ) copied successfully." -Level "SUCCESS"
                
                # Get the job on the target to add the new step
                $targetJob = Get-DbaAgentJob -SqlInstance $TargetServer -Job $jobName -SqlCredential $TargetCredentials
                $jobId = $targetJob.JobID
                $newStepName = "Check if Primary Replica"

                # Use T-SQL to insert the new step at the beginning
                $sqlCommand = @"
-- Ensure job_id is correctly formatted
DECLARE @jobId UNIQUEIDENTIFIER = '$jobId';

-- Shift existing steps down
UPDATE msdb.dbo.sysjobsteps 
SET step_id = step_id + 1
WHERE job_id = @jobId;

-- Add the new step at the beginning
EXEC msdb.dbo.sp_add_jobstep 
    @job_id = @jobId, 
    @step_name = N'$newStepName',
    @step_id = 1,
    @subsystem = N'TSQL',
    @command = N'DECLARE @preferredReplica int

SET @preferredReplica = (SELECT [master].sys.fn_hadr_backup_is_preferred_replica(''$DatabaseName'')) 

IF (@preferredReplica = 1)
BEGIN
     SELECT ''This is the primary replica. Proceeding with the next step...''
END
ELSE 
BEGIN
    RAISERROR(''This is not the primary replica. Aborting job.'', 16, 1)
END',
    @on_success_action = 3,  -- GoToNextStep
    @on_fail_action = 1,     -- QuitWithSuccess (adjust if needed)
    @database_name = N'master'
"@

                # Execute the SQL command to insert the new step
                try {
                    Invoke-DbaQuery -SqlInstance $TargetServer -SqlCredential $TargetCredentials -Query $sqlCommand -Database master | Out-Null
                    Write-Log -Message "New step '$( $newStepName )' added to job $( $jobName )." -Level "INFO"
                } catch {
                    Write-Log -Message "Failed to add new step '$( $newStepName )' to job $( $jobName ). Error: $( $_.Exception.Message )" -Level "ERROR"
                    Write-Log -Message "Error details: $( $_.Exception.InnerException.Message )" -Level "ERROR"
                    throw
                }

                # Disable job on target
                $targetJob | Set-DbaAgentJob -Disabled | Out-Null

                Write-Log -Message "Job $( $jobName ) modified and disabled on target." -Level "INFO"
            } else {
                Write-Log -Message "Failed to copy job $( $jobName )." -Level "ERROR"
            }
        } else {
            Write-Log -Message "No database mapping for job $( $jobName ). Skipping." -Level "WARNING"
        }
    }
}

# Execute migration
Migrate-SQLAgentJobs -SourceServer $SourceServer -TargetServer $TargetServer -JobDatabaseMapping $JobDatabaseMapping -SourceCredentials $SourceCredentials -TargetCredentials $TargetCredentials
