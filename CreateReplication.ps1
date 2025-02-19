<#
.SYNOPSIS
    Creates an entire SQL Server Replication configuration.
#>

param (
    [Parameter(Mandatory=$true)][String]$DistributorInstance,
    [String]$DistributorDatabase = "distribution",
    [Parameter(Mandatory=$true)][String]$PublisherInstance,
    [Parameter(Mandatory=$true)][Array]$PublisherDatabases,
    [Parameter(Mandatory=$true)][Array]$PublisherArticles,
    [Parameter(Mandatory=$true)][String]$SubscriberInstance,
    [String]$DistributionLogin = "distributor_admin",
    [string]$ScriptEventLogPath = "$( $PSScriptRoot )\Logs"
)

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

# Get credential from file on disk
$myCredential = Import-Clixml -Path .\Credentials\myCredentials.xml

# Create distribution login
function Create-Login {
    param (
        [Array]$Instances,
        [String]$Login
    )
    $SecurePassword = Read-Host "Input password for the distribution login..." -AsSecureString
    foreach ($instance in $Instances) {
        if (-not (Test-DbaConnection -SqlInstance $instance)) {
            Write-Log -Message "Failed to connect to instance: $( $instance )" -Level "ERROR"
            throw "Instance connection failed: $instance"
        }
    }
    New-DbaLogin -SqlInstance $Instances -Login $Login -SecurePassword $SecurePassword -PasswordPolicyEnforced
}

# Define function to configure distribution
function Configure-Distribution {
    param (
        [Parameter(Mandatory=$true)]
        [String]$DistributorInstance,
        [String]$DistributorDatabase = "distribution"
    )
    try {
        Write-Log -Message "Configuring distribution on $( $DistributorInstance )" -Level "INFO"
        
        if (-not (Test-DbaConnection -SqlInstance $DistributorInstance)) {
            Write-Log -Message "Failed to connect to the distributor instance: $( $DistributorInstance )" -Level "ERROR"
            throw "Distributor instance connection failed."
        }
        
        Install-DbaReplicationDistributor -SqlInstance $( $DistributorInstance ) -DistributionDBName $( $DistributorDatabase ) -Confirm:$false
        Write-Log -Message "Distribution configured successfully" -Level "SUCCESS"
    }
    catch {
        Write-Log -Message "Failed to configure distribution: $( $_.Exception.Message )" -Level "ERROR"
        throw $_
    }
}

# Define function to configure publication (including articles)
function Configure-Publication {
    param (
        [Parameter(Mandatory=$true)]
        [String]$PublisherInstance,
        [Parameter(Mandatory=$true)]
        [Array]$Databases,
        [Parameter(Mandatory=$true)]
        [String]$PublicationName,
        [Parameter(Mandatory=$true)]
        [String[]]$Articles
    )
    try {
        Write-Log -Message "Configuring publication with articles on $( $PublisherInstance )" -Level "INFO"
        
        if (-not (Test-DbaConnection -SqlInstance $PublisherInstance)) {
            Write-Log -Message "Failed to connect to the publisher instance: $( $PublisherInstance )" -Level "ERROR"
            throw "Publisher instance connection failed."
        }
        
        foreach ($Database in $Databases) {
            # Create the publication for each database
            $pub = New-DbaReplicationPublication -SqlInstance $( $PublisherInstance ) -Database $Database -Name "$( $PublicationName )_$Database" -PublicationType 'Transactional' -AllowInitializeFromBackup

            # Add articles to the publication
            foreach ($article in $Articles) {
                # Check if the article exists in the database before adding
                $tableExists = Test-DbaDbTable -SqlInstance $( $PublisherInstance ) -Database $Database -Table $article
                if ($tableExists) {
                    Add-DbaReplicationArticle -Publication $pub -Name $article -ArticleType 'LogBased'
                    Write-Log -Message "Added article $article to publication $( $PublicationName )_$Database" -Level "INFO"
                } else {
                    Write-Log -Message "Article $article does not exist in the database $Database. Skipping." -Level "WARNING"
                }
            }
        }
        Write-Log -Message "Publication configuration completed successfully" -Level "SUCCESS"
    }
    catch {
        Write-Log -Message "Failed to configure publication with articles: $( $_.Exception.Message )" -Level "ERROR"
        throw $_
    }
}

# Define function to configure subscription
function Configure-Subscription {
    param (
        [Parameter(Mandatory=$true)]
        [String]$PublisherInstance,
        [Parameter(Mandatory=$true)]
        [String]$PublicationName,
        [Parameter(Mandatory=$true)]
        [String]$SubscriberInstance,
        [Parameter(Mandatory=$true)]
        [String]$SubscriptionDatabase
    )
    try {
        Write-Log -Message "Configuring subscription to $( $PublicationName ) from $( $PublisherInstance ) to $( $SubscriberInstance )" -Level "INFO"
        
        if (-not (Test-DbaConnection -SqlInstance $SubscriberInstance)) {
            Write-Log -Message "Failed to connect to the subscriber instance: $( $SubscriberInstance )" -Level "ERROR"
            throw "Subscriber instance connection failed."
        }
        
        New-DbaReplicationSubscription -Publisher $( $PublisherInstance ) -Publication $( $PublicationName ) -Subscriber $( $SubscriberInstance ) -DestinationDatabase $( $SubscriptionDatabase ) -SubscriptionType 'Push' -InitializeFromBackup
        Write-Log -Message "Subscription configured successfully" -Level "SUCCESS"
    }
    catch {
        Write-Log -Message "Failed to configure subscription: $( $_.Exception.Message )" -Level "ERROR"
        throw $_
    }
}

############################
### Main execution block ###
############################

try {
    Create-Login -Instances $DistributorInstance, $PublisherInstance, $SubscriberInstance -Login $DistributionLogin
    Configure-Distribution -DistributorInstance $DistributorInstance -DistributorDatabase $DistributorDatabase
    Configure-Publication -PublisherInstance $PublisherInstance -Databases $PublisherDatabases -PublicationName "MyPublication" -Articles $PublisherArticles
    
    foreach ($Database in $PublisherDatabases) {
        $SubscriptionDatabaseName = "SubDB_" + $Database
        Configure-Subscription -PublisherInstance $PublisherInstance -PublicationName "MyPublication_$Database" -SubscriberInstance $SubscriberInstance -SubscriptionDatabase $SubscriptionDatabaseName
    }
}
catch {
    Write-Log -Message "An error occurred during the replication setup: $( $_.Exception.Message )" -Level "ERROR"
    throw $_
}
