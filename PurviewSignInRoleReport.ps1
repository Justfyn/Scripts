############################################################################
#This sample script is not supported under any Microsoft standard support program or service.
#This sample script is provided AS IS without warranty of any kind.
#Microsoft further disclaims all implied warranties including, without limitation, any implied
#warranties of merchantability or of fitness for a particular purpose. The entire risk arising
#out of the use or performance of the sample script and documentation remains with you. In no
#event shall Microsoft, its authors, or anyone else involved in the creation, production, or
#delivery of the scripts be liable for any damages whatsoever (including, without limitation,
#damages for loss of business profits, business interruption, loss of business information,
#or other pecuniary loss) arising out of the use of or inability to use the sample script or
#documentation, even if Microsoft has been advised of the possibility of such damages.
############################################################################


#Requires -Version 4
#Requires -Modules @{ModuleName='Microsoft.Graph.Authentication';ModuleVersion='2.0.0'},ExchangeOnlineManagement

<#
.SYNOPSIS
    Reports on users signing into the Microsoft Purview / Security & Compliance Center and their administrative roles.

.DESCRIPTION
    This script identifies users who have signed into the specified Microsoft Purview / Security & Compliance Center 
    application ID within a defined timeframe using the Microsoft Graph Advanced Hunting API. 
    It then retrieves the assigned Entra ID directory roles and Security & Compliance (SCC) roles 
    for each of those users and outputs the results to an HTML report.

    The script requires appropriate Microsoft Graph permissions, including ThreatHunting.Read.All, 
    and potentially specific Microsoft 365 licenses for Advanced Hunting functionality. 
    It operates within the Microsoft 365 Commercial Cloud environment.

.PARAMETER AdminUPN
    Optional. The User Principal Name (UPN) of an account used for connecting to the Security & Compliance 
    Center PowerShell endpoint. If not provided, and a connection is needed, the script will prompt for it. 
    Providing this can help avoid interactive prompts if the session requires reconnection.

.PARAMETER IgnoredRoles
    Optional. An array of role display names (case-sensitive) to exclude from the final report. 
    This applies to both Entra ID directory roles and SCC role groups.
    Default value includes the standard Entra role "Directory Synchronization Accounts".

.PARAMETER Output
    Optional. The full path and filename for the generated HTML report.
    Default: ".\PurviewSignInRoleReport.html" in the current script directory.

.PARAMETER AppIdForSignInCheck
    Optional. The Application (client) ID of the Entra application for which sign-in activity is checked.
    Default: '80ccca67-54bd-44ab-8625-4b79c4dc7775' (Microsoft Purview / Security & Compliance Center).

.PARAMETER SignInDaysThreshold
    Optional. The number of days into the past to check for sign-in activity.
    Default: 30.

.NOTES
    Version: 5.1
    Date: 2025-04-14

    - Uses the Microsoft Graph Advanced Hunting API (/security/runHuntingQuery) to efficiently find users signing into the target application.
    - Reports ONLY on users identified via the Advanced Hunting sign-in query.
    - Builds maps of Entra ID and SCC role memberships for efficient lookup.
    - Requires Microsoft Graph Permissions: 
        - ThreatHunting.Read.All (for Advanced Hunting query)
        - Directory.Read.All (for user details, group memberships)
        - RoleManagement.Read.Directory (for Entra role definitions/assignments)
        - GroupMember.Read.All (for resolving SCC group memberships via Graph)
    - Requires appropriate Entra ID roles for the account running the script (e.g., Global Reader or roles granting the specific Graph permissions).
    - Advanced Hunting API access and underlying data tables (e.g., SigninLogs) may depend on specific Microsoft 365 / Microsoft Defender licenses (e.g., E5/A5/G5 level). Verify licensing in your environment.
    - Designed for Microsoft 365 Commercial Cloud ONLY.
    - Uses Bootstrap CSS for HTML report formatting.

.EXAMPLE
    .\Get-SccSignInReport.ps1 -AdminUPN "admin@contoso.com" -SignInDaysThreshold 7 -Output "C:\Reports\SCC_SignIns_Last7Days.html"
    Runs the report for the last 7 days, using the specified admin UPN for SCC connections, saving the report to C:\Reports.

.EXAMPLE
    .\Get-SccSignInReport.ps1 -IgnoredRoles @("Directory Synchronization Accounts", "Custom Role To Ignore")
    Runs the report with default settings but excludes an additional custom role from the results.
#>

[CmdletBinding()]
Param(
    [String]$Output = "PurviewSignInRoleReport.html",
    [array]$IgnoredRoles=@("Directory Synchronization Accounts"), # Use [array] for type safety
	[string]$AdminUPN,
    [string]$AppIdForSignInCheck = '80ccca67-54bd-44ab-8625-4b79c4dc7775',
    [int]$SignInDaysThreshold = 30
)

# --- FUNCTION DEFINITIONS ---

function Get-UserDetailsWithCache ($UserIdParameter) {
    # Retrieves basic user or service principal details, using a script-scoped cache.

    # Check cache first
    if ($script:directoryObjectsCache.ContainsKey($UserIdParameter)) {
        Write-Verbose "[Cache] Returning details for $UserIdParameter."
        return $script:directoryObjectsCache[$UserIdParameter]
    }

    Write-Verbose "[API] Getting details for object $UserIdParameter."
    # Initialize default values
    $objectDetails = [PSCustomObject]@{
        SignInName   = "$UserIdParameter (Unknown type)"
        AccountState = $null
        UserType     = "Unknown"
    }

    try {
        # Attempt to get as a User object
        $userSelectFields = 'id,userPrincipalName,accountEnabled,onPremisesImmutableId'
        $userUri = "/v1.0/users/$($UserIdParameter)?`$select=$userSelectFields"
        $user = Invoke-MgGraphRequest -Method GET -Uri $userUri -OutputType PSObject -ErrorAction SilentlyContinue # Continue if not a user

        if ($user) {
            # User found, populate details
            $objectDetails.SignInName = $user.userPrincipalName
            $objectDetails.AccountState = if ($user.accountEnabled -eq $true) { "Enabled" } else { "Disabled" }
            $objectDetails.UserType = if ($null -eq $user.onPremisesImmutableId) { "Cloud" } else { "Synced" }
        } else {
            # Not a user, try as a generic directory object
            $dirObjectSelectFields = 'id,displayName' # '@odata.type' is usually returned by default
            $dirObjectUri = "/v1.0/directoryObjects/$($UserIdParameter)?`$select=$dirObjectSelectFields"
            $dirObject = Invoke-MgGraphRequest -Method GET -Uri $dirObjectUri -OutputType PSObject -ErrorAction Stop # Stop if not found at all

            # Check if it's a known type like Service Principal
            if ($dirObject.'@odata.type' -eq "#microsoft.graph.servicePrincipal") {
                $objectDetails.SignInName = "$($dirObject.displayName) (Service Principal)"
                $objectDetails.UserType = 'Cloud'
                $objectDetails.AccountState = 'N/A' # Not applicable state for SP
            } else {
                 # Other object type
                 $objectDetails.SignInName = "$($dirObject.displayName) ($($dirObject.'@odata.type'))"
                 $objectDetails.UserType = "Other"
                 $objectDetails.AccountState = 'N/A'
            }
        }
    } catch {
        # Format error message safely using -f operator
        $warningMessage = "[Get-UserDetails] Error retrieving details for ID {0}: {1}" -f $UserIdParameter, $_.Exception.Message
        Write-Warning $warningMessage
        $objectDetails.SignInName = "$UserIdParameter (Error retrieving details)" # Update SignInName to indicate error
    }

    # Add retrieved details to cache before returning
    $script:directoryObjectsCache[$UserIdParameter] = $objectDetails
    return $objectDetails
}

function Get-SccRoleMap {
    # Builds a map of UserId -> @(SCC Role Names). Connects to SCC if necessary.
    param([string]$AdminUPN, [array]$IgnoredRoles)

    $sccRoleMap = @{} # Hashtable to store mapping: $sccRoleMap[UserId] = List<string> of Role Names

    # Ensure SCC connection exists or establish a new one
    if (-not(Get-Command -Name Get-SCCRoleGroup -ErrorAction SilentlyContinue)) {
		Write-Host "Connecting to Security & Compliance Center PowerShell..."
		if (-not $AdminUPN) {
			# Prompt for UPN if not provided as parameter
			do { $localAdminUPN = Read-Host "Enter UPN for SCC connection" }
			until ($localAdminUPN -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$") # Basic UPN validation
			$AdminUPN = $localAdminUPN # Use the interactively provided UPN
            Write-Host ""
		}
        if (-not $AdminUPN) { Write-Error "AdminUPN is required to connect to SCC."; return $null } # Cannot proceed

		try {
            # Define connection parameters for Connect-IPPSSession
            $connectParams = @{
                UserPrincipalName = $AdminUPN
                Prefix            = "SCC" # Prefix SCC commands (e.g., Get-SCCRoleGroup)
                WarningAction     = "SilentlyContinue"
                ShowBanner        = $false
                ErrorAction       = "Stop"
            }
            # Connect using default endpoints for Commercial cloud
            Connect-IPPSSession @connectParams | Out-Null
            Write-Host "Successfully connected to SCC PowerShell."
        } catch {
            Write-Error "Failed to connect to SCC PowerShell. SCC roles cannot be mapped. Error: $($_.Exception.Message)"
            return $null # Return null indicates failure
        }
	} else {
        Write-Host "Using existing SCC PowerShell connection."
    }

    Write-Host "Building Security & Compliance role membership map..."
    $sccRoles = $null
    try {
        # Retrieve all SCC role groups
        $sccRoles = Get-SCCRoleGroup -ErrorAction Stop
    } catch {
        Write-Error "Failed to retrieve SCC role groups. Error: $($_.Exception.Message)"
        return $sccRoleMap # Return map as is (likely empty)
    }

    # Filter out roles specified in the $IgnoredRoles parameter
    $rolesToProcess = $sccRoles | Where-Object {$_.DisplayName -notin $IgnoredRoles}
    $totalRoles = $rolesToProcess.Count
    $roleCounter = 0

    if ($totalRoles -eq 0) {
         Write-Host "No SCC roles found or all roles were ignored."
         return $sccRoleMap
    }

    # Iterate through each relevant SCC role group
    foreach ($sccRole in $rolesToProcess) {
        $roleCounter++
        $roleName = $sccRole.DisplayName
        # Use -f format operator for safe string construction in Write-Progress
        $statusString = "Processing SCC Role {0}/{1}: {2}" -f $roleCounter, $totalRoles, $roleName
        $progressParams = @{
            Activity        = "Mapping SCC Roles"
            Status          = $statusString
            PercentComplete = (($roleCounter / $totalRoles) * 100)
        }
        Write-Progress @progressParams
        Write-Verbose "Processing SCC Role: $roleName"

        # Use a HashSet for efficient storage of unique member IDs for this role
        $memberIdsInRole = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $sccMembers = @()

        try {
            # Get direct members of the current role group
            $sccMembers = Get-SCCRoleGroupMember -Identity $sccRole.Guid.Guid -ErrorAction Stop
        } catch {
            Write-Warning "Failed to get members for SCC role '$($roleName)': $($_.Exception.Message)"
            continue # Skip to the next role group
        }

        # Process each direct member
        foreach ($sMember in $sccMembers) {
            if ($sMember.RecipientType -like '*group') {
                # Member is a group, need to resolve its members using Graph
                $groupDisplayName = $sMember.DisplayName
                $groupId = $sMember.Guid.Guid
                Write-Verbose "Resolving Group membership: $groupDisplayName (for role '$roleName')"
                $groupMembers = @()
                try {
                    # Get transitive members (includes members of nested groups)
                    # Select only the 'id' property as that's all we need here
                    $graphMemberUri = "/beta/groups/$groupId/transitiveMembers?`$top=999&`$select=id" # Using Beta for transitive members
                    $graphRequestParams = @{
                        Method = 'GET'
                        Uri = $graphMemberUri
                        OutputType = 'PSObject'
                        ErrorAction = 'Stop'
                    }
                    # Simple retry loop for potential throttling
                    $retryCount = 0; $maxRetries = 2; $graphResponse = $null
                    while($retryCount -le $maxRetries) {
                        try { $graphResponse = Invoke-MgGraphRequest @graphRequestParams; break }
                        catch { $retryCount++; if($retryCount -gt $maxRetries) {throw}; Write-Warning "Graph group member query throttled/failed, retrying ($retryCount/$maxRetries)..."; Start-Sleep -Seconds (Get-Random -Min 3 -Max 5)*$retryCount }
                    }

                    $groupMembers = $graphResponse.value
                } catch {
                    Write-Warning "Failed to get Graph members for group '$groupDisplayName'. Error: $($_.Exception.Message)"
                }

                if ($groupMembers) {
                    # Add only non-group objects (users, service principals) to the set for this role
                    foreach ($mMember in ($groupMembers | Where-Object { $_."@odata.type" -ne "#microsoft.graph.group" })) {
                        if ($mMember.id) { [void]$memberIdsInRole.Add($mMember.id) }
                    }
                }
            } else {
                # Member is a direct user or other object type
                if ($sMember.Guid) { [void]$memberIdsInRole.Add($sMember.Guid.Guid) }
            }
        } # End foreach direct member

        # Add this role mapping to the main hashtable for each identified member
        foreach ($userId in $memberIdsInRole) {
            if (-not $sccRoleMap.ContainsKey($userId)) {
                # Initialize a new List for this user if they aren't in the map yet
                $sccRoleMap[$userId] = [System.Collections.Generic.List[string]]::new()
            }
            # Add the role name if it's not already listed for this user
            if ($sccRoleMap[$userId] -notcontains $roleName) {
                $sccRoleMap[$userId].Add($roleName)
                Write-Verbose "Mapped User $userId to SCC Role '$roleName'"
            }
        }
    } # End foreach SCC Role

    Write-Progress -Activity "Mapping SCC Roles" -Completed
    Write-Host "Finished building SCC role map. Mapped $($sccRoleMap.Count) unique users to one or more SCC roles."
    return $sccRoleMap
}

function Get-EntraRoleMapOptimized {
    # Builds a map of UserId -> @(Entra Role Names) using an optimized query.
    param( [array]$IgnoredRoles )

    Write-Host "Building Entra ID directory role membership map (Optimized)..."
    $entraRoleMap = @{} # Hashtable: $entraRoleMap[UserId] = List<string> of Role Names
    $allAssignments = @() # List to store all role assignment objects

    # Construct the Graph API URI to get all role assignments and expand the role definition name
    $assignmentSelect = 'principalId' # We need the ID of the assigned principal (user, SP, group)
    $assignmentExpand = 'roleDefinition($select=displayName)' # Expand definition to get name
    $assignmentUri = "/v1.0/roleManagement/directory/roleAssignments?`$select=$assignmentSelect&`$expand=$assignmentExpand&`$top=999"
    $pageCount = 0

    try {
         Write-Host "Querying Microsoft Graph for all Entra role assignments..."
         # Loop to handle pagination using @odata.nextLink
         do {
            $pageCount++
            Write-Host "Requesting Entra assignment data page $pageCount..."
            # Define parameters for Invoke-MgGraphRequest
            $graphRequestParams = @{
                Method      = 'GET'
                Uri         = $assignmentUri
                OutputType  = 'PSObject'
                ErrorAction = 'Stop'
            }
            $response = $null
            # Simple retry loop for potential throttling (can be enhanced)
            $retryCount = 0; $maxRetries = 2;
            while($retryCount -le $maxRetries) {
                try { $response = Invoke-MgGraphRequest @graphRequestParams; break } # Success
                catch {
                    $retryCount++
                    if($retryCount -gt $maxRetries) { throw } # Max retries exceeded
                    Write-Warning "Entra assignment query throttled/failed, retrying ($retryCount/$maxRetries)..."; Start-Sleep -Seconds (Get-Random -Min 3 -Max 5)*$retryCount
                }
            }

            # Process the response if valid
            if ($response -and $response.value) {
                Write-Host "Retrieved $($response.value.Count) assignments on page $pageCount."
                $allAssignments += $response.value # Add assignments from current page
                # Check for next page link
                $assignmentUri = $response.'@odata.nextLink'
                if ($assignmentUri) {
                    # Prepare URI for next iteration (remove base URL)
                    $assignmentUri = $assignmentUri -replace 'https://graph.microsoft.com/v1.0', ''
                    Write-Verbose "Next page link found for Entra assignments."
                }
            } else {
                Write-Verbose "No assignment data or no 'value' property on page $pageCount."
                $assignmentUri = $null # Stop loop if no more data
            }
         } while ($assignmentUri) # Continue loop if there's a nextLink

         Write-Host "Finished querying Entra assignments. Total assignment records retrieved: $($allAssignments.Count)."

         # Process the collected assignments to build the UserID -> Roles map
         Write-Host "Processing assignments into Entra role map..."
         foreach ($assignment in $allAssignments) {
            $userId = $assignment.principalId
            $roleName = $assignment.roleDefinition.displayName

            # Basic validation and filtering of ignored roles
            if (-not $userId -or -not $roleName -or $roleName -in $IgnoredRoles) {
                continue # Skip invalid entries or ignored roles
            }

            # Add the user and role to the map
            if (-not $entraRoleMap.ContainsKey($userId)) {
                # Initialize list if user not seen before
                $entraRoleMap[$userId] = [System.Collections.Generic.List[string]]::new()
            }
            if ($entraRoleMap[$userId] -notcontains $roleName) {
                # Add role if not already present for this user
                $entraRoleMap[$userId].Add($roleName)
                Write-Verbose "Mapped User $userId to Entra Role '$roleName'"
            }
         } # End foreach assignment processing

    } catch {
        Write-Error "Failed during Entra role assignment query or processing: $($_.Exception.Message)"
        # Return the map as is (may be incomplete)
    }

    Write-Host "Finished building Entra role map. Mapped $($entraRoleMap.Count) unique users to one or more Entra roles."
    return $entraRoleMap
}

function Get-SignInUsersViaHunting {
    # Gets distinct users signing into an App ID using Advanced Hunting.
    param(
        [string]$AppId,
        [int]$DaysAgo
    )
    Write-Host "Querying Advanced Hunting for successful sign-ins to App ID '$AppId' (Last $($DaysAgo) days)..."

    # KQL query to find successful sign-ins and get distinct User IDs and UPNs
    # Using ResultType == 0 for Success based on SigninLogs schema
    $kqlQuery = @"
SigninLogs
| where TimeGenerated > ago($($DaysAgo)d)
| where AppId == '$AppId' and ResultType == 0 
| summarize count() by UserId, UserPrincipalName // Use summarize to get distinct UserId/UPN pairs
| project UserId, UserPrincipalName // Project only needed columns
"@
    # Prepare the request body for the API
    $requestBody = @{ Query = $kqlQuery } | ConvertTo-Json

    $huntingUri = "/v1.0/security/runHuntingQuery"
    $huntingResults = $null # Store the 'results' array from the response

    try {
        # Define parameters for Invoke-MgGraphRequest
        $graphRequestParams = @{
            Method      = 'POST'
            Uri         = $huntingUri
            Body        = $requestBody
            ContentType = "application/json"
            ErrorAction = 'Stop'
        }
        $response = Invoke-MgGraphRequest @graphRequestParams

        # Check the response structure
        if ($response -and $response.results) {
            $huntingResults = $response.results
            Write-Host "Advanced Hunting query successful. Found $($huntingResults.Count) distinct user sign-ins."
        } else {
            # Handle cases where query ran but returned no results or unexpected format
            Write-Warning "Advanced Hunting query ran but returned no results property or the property was empty."
            $huntingResults = @() # Ensure an empty array is returned, not null
        }
    } catch {
        Write-Error "Advanced Hunting query failed. Please verify ThreatHunting.Read.All permission and necessary licenses (e.g., E5/Defender P2). Error: $($_.Exception.Message)"
        # Consider tenant capabilities: Check if 'SigninLogs' table exists? (More advanced)
        $huntingResults = $null # Indicate failure by returning null
    }

    # Return the array of result objects (each should have UserId, UserPrincipalName)
    return $huntingResults
}

# --- END FUNCTION DEFINITIONS ---


# --- SCRIPT BODY ---

# **Initialization**
$scriptStartTime = Get-Date
Write-Host "Script started at $scriptStartTime"
$reportData = [System.Collections.Generic.List[PSCustomObject]]::new()
# Cache for user details, keyed by UserId (string)
$script:directoryObjectsCache = [System.Collections.Concurrent.ConcurrentDictionary[string,psobject]]::new([System.StringComparer]::OrdinalIgnoreCase)


# **Connections & Scope Check**
# Define required Microsoft Graph permissions
$requiredScopes = @(
    'Directory.Read.All',           # For User Details, Group Membership Resolution
    'RoleManagement.Read.Directory',# For Entra Role Definitions/Assignments
    'GroupMember.Read.All',         # For SCC Group Membership Resolution via Graph
    'ThreatHunting.Read.All'        # For Advanced Hunting API query
) | Select-Object -Unique

# Check current Graph connection and scopes
$graphConnectParams = @{ ErrorAction = 'Stop' } # Common params for Connect-MgGraph
$graphConnectNeeded = $false
try {
    # Attempt to get current context; fails if not connected
    $currentContext = Get-MgContext -ErrorAction Stop
    $currentScopes = $currentContext.Scopes
    # Verify all required scopes are present
    foreach ($scope in $requiredScopes) {
        if ($currentScopes -notcontains $scope) {
            Write-Warning "Current Graph session is missing required scope: $scope"
            $graphConnectNeeded = $true
            break # No need to check further scopes
        }
    }
    if (-not $graphConnectNeeded) { Write-Host "Using existing Microsoft Graph connection with sufficient scopes." }
} catch {
    # Get-MgContext failed, likely not connected
    $graphConnectNeeded = $true
}

# Connect or Reconnect to Graph if needed
if ($graphConnectNeeded) {
    Write-Host "Attempting to connect to Microsoft Graph..."
    try {
        # Ensure clean state if reconnecting
        if (Get-MgContext -ErrorAction SilentlyContinue) { Disconnect-MgGraph }
        # Connect requesting all required scopes
        Connect-MgGraph -ContextScope Process -Scopes $requiredScopes -NoWelcome @graphConnectParams
        Write-Host "Successfully connected to Microsoft Graph."
    } catch {
        Write-Error "Failed to connect to Microsoft Graph with required scopes. Please ensure permissions are granted. Error: $($_.Exception.Message)"
        exit # Exit script if essential connection fails
    }
}
# SCC Connection is handled within the Get-SccRoleMap function

# **Step 1: Get Signed-in Users via Advanced Hunting**
# Execute the hunting query to find users who signed into the SCC app
$signInUsers = Get-SignInUsersViaHunting -AppId $AppIdForSignInCheck -DaysAgo $SignInDaysThreshold
if ($null -eq $signInUsers) {
    Write-Error "Could not retrieve sign-in user list via Advanced Hunting. Exiting."
    exit
}
if ($signInUsers.Count -eq 0) {
    Write-Warning "No users found signing into App ID '$AppIdForSignInCheck' via Advanced Hunting in the last $SignInDaysThreshold days. No report will be generated."
    exit # Exit if no users signed in
}

# Extract unique User IDs from the results (Advanced Hunting might return duplicates if summarize isn't perfect)
$uniqueSignInUserIds = $signInUsers.UserId | Where-Object { $_ } | Select-Object -Unique
Write-Host "Identified $($uniqueSignInUserIds.Count) unique users signing into '$AppIdForSignInCheck' (via Advanced Hunting)."

# **Step 2: Build SCC Role Map**
# Get mapping of UserId -> SCC Roles
$sccRoleMap = Get-SccRoleMap -AdminUPN $AdminUPN -IgnoredRoles $IgnoredRoles
if ($null -eq $sccRoleMap) {
    # Allow script to continue, but SCC roles will be missing
    Write-Warning "Failed to build SCC role map. Report will not include SCC roles."
    $sccRoleMap = @{} # Ensure it's a valid, empty hashtable
}

# **Step 3: Build Entra Role Map (Optimized)**
# Get mapping of UserId -> Entra Roles
$entraRoleMap = Get-EntraRoleMapOptimized -IgnoredRoles $IgnoredRoles
if ($null -eq $entraRoleMap) {
     # Allow script to continue, but Entra roles will be missing
    Write-Warning "Failed to build Entra role map. Report will not include Entra roles."
    $entraRoleMap = @{} # Ensure it's a valid, empty hashtable
}

# **Step 4: Process Signed-in Users**
Write-Host "Processing details and roles for each signed-in user..."
$userCounter = 0
$totalUsersToProcess = $uniqueSignInUserIds.Count

# Iterate through the list of unique user IDs obtained from the sign-in query
foreach ($userId in $uniqueSignInUserIds) {
    $userCounter++
    # Update progress bar
    $progressParams = @{
        Activity        = "Processing Signed-in Users"
        Status          = "Processing User $userCounter / $totalUsersToProcess ($userId)"
        PercentComplete = (($userCounter / $totalUsersToProcess) * 100)
    }
    Write-Progress @progressParams

    # Get Basic User Details (using cache)
    $userDetails = Get-UserDetailsWithCache -UserIdParameter $userId

    # Lookup Entra Roles for this user from the pre-built map
    $entraRoles = if ($entraRoleMap.ContainsKey($userId)) { $entraRoleMap[$userId] } else { @() }

    # Lookup SCC Roles for this user from the pre-built map
    $sccRoles = if ($sccRoleMap.ContainsKey($userId)) { $sccRoleMap[$userId] } else { @() }

    # Combine and Format Roles (Roles from maps are already filtered by IgnoredRoles)
    $formattedRoles = [System.Collections.Generic.List[string]]::new()
    $entraRoles | ForEach-Object { $formattedRoles.Add("[Entra] $_") } # Prefix to indicate source
    $sccRoles | ForEach-Object { $formattedRoles.Add("[Purview] $_") }     # Prefix to indicate source

    $allRoles = $formattedRoles | Select-Object -Unique | Sort-Object # Get unique, sorted list
    $roleString = if ($allRoles.Count -gt 0) {
        $allRoles -join '; ' # Join roles with semicolon if found
    } else {
        "-- No Roles Found --" # Explicitly state if no relevant roles were mapped
    }

    # Add the collected information for this user to the report data list
    $reportData.Add([PSCustomObject]@{
        SignInName   = $userDetails.SignInName
        UserType     = $userDetails.UserType
        AccountState = $userDetails.AccountState
        AdminRoles   = $roleString  # String containing combined/formatted roles
    })

} # End foreach user loop
Write-Progress -Activity "Processing Signed-in Users" -Completed

# --- REPORT GENERATION ---
if ($reportData.Count -gt 0) {
	Write-Host "Generating HTML report..."
    # Standard Bootstrap styling is usually sufficient
    $css = ""

    # Construct HTML Header and Title section
	$Report = "<html><head><title>Purview Sign-in & Admin Role Report</title><link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css' integrity='sha384-xOolHFLEh07PJGoPkLv1IbcEPTNtaed2xpHsD9ESMhqIYd0nLMwNLD69Npy4HI+N' crossorigin='anonymous'>$($css)</head><body>"
	$Report += "<div class='jumbotron jumbotron-fluid'><div class='container'>"
    $Report += "<h1 class='display-4'>Purview Sign-in & Admin Role Report</h1>"
    $Report += "<p class='lead'>List of users who signed into Application ID '$($AppIdForSignInCheck)' within the last $($SignInDaysThreshold) days, along with their detected Entra ID and Security & Compliance admin roles.</p>"
    $Report += "<p class='text-muted'>Sign-in data retrieved via Advanced Hunting API. Report generated on $((Get-Date).ToLocalTime()).</p>"
    $Report += "</div></div>" # Close jumbotron

    # Construct HTML Table
    $Report += "<div class='container'>" # Add container for padding/alignment
    $Report += "<table class='table table-striped table-hover table-sm'>" # Standard Bootstrap table classes
    $Report += "<thead class='thead-light'>" # Light header background
    $Report += "<tr><th>Sign-in Name / UPN</th><th>Type</th><th>Account State</th><th>Detected Admin Roles (Entra/SCC)</th></tr>" # Table Headers
    $Report += "</thead>"
    $Report += "<tbody>"

    # Add a row for each user in the report data, sorted by SignInName
    foreach($row in ($reportData | Sort-Object SignInName)) {
        $Report += "<tr>"
        # Escape potential HTML characters in data using helper or simple replace
        $Report += "<td>$($row.SignInName -replace '<','<' -replace '>','>')</td>"
        $Report += "<td>$($row.UserType -replace '<','<' -replace '>','>')</td>"
        $Report += "<td>$($row.AccountState -replace '<','<' -replace '>','>')</td>"
        $Report += "<td>$($row.AdminRoles -replace '<','<' -replace '>','>')</td>"
        $Report += "</tr>"
    }

    $Report += "</tbody></table>"
    $Report += "</div>" # Close container
    $Report += "</body></html>" # Close HTML

    # Save the report to file
	try {
        $Report | Out-File -FilePath $Output -Encoding UTF8 -ErrorAction Stop
        Write-Host "Successfully generated HTML report: '$Output'"
        # Offer to open the report
        Invoke-Item $Output
    } catch {
        Write-Error "Failed to save HTML report to '$Output'. Error: $($_.Exception.Message)"
    }

} else {
    # This case should ideally be caught earlier if no sign-ins were found
    Write-Warning "No data available to generate report. This might happen if no users signed in or errors occurred during processing."
}

# Disconnect PowerShell sessions if they were opened by this script
# Check for SCC session specifically opened with 'SCC' prefix
if (Get-Command -Name Disconnect-IPPSSession -ErrorAction SilentlyContinue) {
    $sccSessions = Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' -and ($_.Module -like '*ExchangeOnlineManagement*' -or $_.Module -like '*tmpEXO*') -and $_.Name -like 'SCC*' }
    if ($sccSessions) {
        Write-Host "Disconnecting from Security & Compliance Center PowerShell session(s)..."
        $sccSessions | Remove-PSSession -ErrorAction SilentlyContinue
    }
}

$scriptEndTime = Get-Date
Write-Host "Script finished at $scriptEndTime. Total runtime: $($scriptEndTime - $scriptStartTime)."
# --- END OF SCRIPT ---