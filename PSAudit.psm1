<#
.Synopsis
   Gets events from security logs.
.DESCRIPTION
   Gets events from security logs. Can process multiple computers or multiple files.
.EXAMPLE
   Get-PSSecurityEvent -Path $files -EventID $category.ID -UserPosition $category.UserPosition -Verbose
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-PSSecurityEvent
{
    [CmdletBinding()]
    [Alias()]
    #[OutputType([int])]
    Param
    (
        #Specifies the name of the computer(s) to gets events.
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0,
                   ParameterSetName='ComputerName',
                   HelpMessage="Specifies the name of the computer(s) to gets events.")]
        [string[]]$ComputerName,
         
        #Specifies the path(s) of the log file
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0,
                   ParameterSetName='Path',
                   HelpMessage="Specifies the path(s) of the log file")]
        [string[]]$Path, 

        [Parameter(Mandatory=$true,
                    Position=1,
                    HelpMessage="EventID")]
        [string]$EventID,

        #Position Of User Name in Message
        [Parameter(Position=2,
                    HelpMessage="Position Of User Name in Message")]
        [int]
        $UserPosition = 5 
    )

    Begin
    {
        $filterComputer = @{logname='Security';ID="$EventID"}
        $filterPath = @{ID="$EventID";Path=""}
    }
    Process
    {
        if ($ComputerName)
        {
#region Computer
            foreach ($computer in $ComputerName)
            {
                Write-Verbose "Getting EventID: $EventID from $computer"

                try
                {
                    Get-WinEvent -ComputerName $computer -FilterHashtable $filterComputer -ErrorAction Stop |
                    Select-Object -Property TimeCreated, RecordID, MachineName, Properties |
                    Foreach-Object {
                        $props = @{'Source'=$_.MachineName;
                                'RecordId'=$_.RecordID;
                                'TimeCreated'=$_.TimeCreated;
                                'User'=$($_.Properties.Value[$UserPosition]);
                                'Domain'=$($_.Properties.Value[$UserPosition + 1])}

                        $obj = New-Object -TypeName psobject -Property $props
                        Write-Output $obj
                    }


                } #end try
                catch [System.Diagnostics.Eventing.Reader.EventLogException]
                {
                    #$_
                   # Write-Error "Computer Offline or no matching entries"
                
                    $props = @{'Source'=$computer;
                                'RecordId'=$null;
                                'TimeCreated'=$null;
                                'User'=$null;
                                'Domain'=$null}

                    $obj = New-Object -TypeName psobject -Property $props
                    Write-Output $obj

                } #end catch
                catch #Most likely, no events found
                {
                    Write-Error $_
                
                    $props = @{'Source'=$computer;
                                'RecordID'=$null;
                                'TimeCreated'=$null;
                                'User'=$null;
                                'Domain'=$null}

                    $obj = New-Object -TypeName psobject -Property $props
                    Write-Output $obj
                } #end catch
            } #end foreach
        
#endregion Computer
        } #end if
        else
        {
#region Path...
            foreach ($file in $Path)
            {
                Write-Verbose "Getting EventID: $EventID from $file"
                $filterPath.Path = $file

                try
                {
                    Get-WinEvent -FilterHashtable $filterPath -ErrorAction Stop |
                    Foreach-Object {
                        $props = @{'Source'=$file;
                                'MachineName'=$_.MachineName;
                                'RecordId'=$_.RecordID;
                                'TimeCreated'=$_.TimeCreated;
                                'User'=$($_.Properties.Value[$UserPosition]);
                                'Domain'=$($_.Properties.Value[$UserPosition + 1])}

                        $obj = New-Object -TypeName psobject -Property $props
                        Write-Output $obj
                    }
                } #end try
                catch [System.Diagnostics.Eventing.Reader.EventLogException]
                {
                    #$_
                   # Write-Error "Computer Offline or no matching entries"
                
                    $props = @{'Source'=$file;
                                'RecordID'=$null;
                                'TimeCreated'=$null;
                                'User'=$null;
                                'Domain'=$null}

                    $obj = New-Object -TypeName psobject -Property $props
                    Write-Output $obj
                }
                catch #Most likely, no events found
                {
                    Write-Error $_
                
                    $props = @{'Source'=$file;
                                'RecordID'=$null;
                                'TimeCreated'=$null;
                                'User'=$null;
                                'Domain'=$null}

                    $obj = New-Object -TypeName psobject -Property $props
                    Write-Output $obj
                }      
            } #end foreach
#endregion Path
        } #end elseGet
    } #end Process
    End
    {

    }
} #End Get-PSSecurityEvent


<#
.Synopsis
   Creates a new audit report.
.DESCRIPTION
   Creates a new audit report.  This is an interactive function.
   Output will be written to the current directory.
   Non-interactive support should be added.
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function New-PSAudit
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
    )


        if ($Path -eq $null)
        {
            Write-Host "Please put all security logs for analysis in a folder."
            Write-Host "Select a folder for analysis..."
        }

        $path = Get-Folder

        if ($path -eq $null)
        {
            Write-Error "No path"
            break
        }

        $files = (Get-ChildItem -Path $path -Filter "*.evtx").FullName

        $auditCategories = Import-Csv -Path "$PSScriptRoot/audit_categories.csv"
        $reportCategories = ($auditCategories | Select-Object -Property Report -Unique).Report

        $style = "<style>
            h2, h5, th { text-align: center; } 
            table { margin: auto; font-family: Segoe UI; box-shadow: 10px 10px 5px #888; border: thin ridge grey; } 
            th { background: #0046c3; color: #fff; max-width: 400px; padding: 5px 10px; } 
            td { font-size: 11px; padding: 5px 20px; color: #000; } 
            tr { background: #b8d1f3; } 
            tr:nth-child(even) { background: #dae5f4; } 
            tr:nth-child(odd) { background: #b8d1f3; }
            tr:hover{background-color:#FFFF00}
            h2 {color: red;}
            </style>"



    foreach($report in $reportCategories)
    {
        $htmlTables = @()
        Write-Verbose "`nProcessing Report: $report`n"

        foreach ($category in $auditCategories)
        {
            Write-Verbose "Processing $($category.ID) for $report"
            if ( "$($category.Report)" -eq "$report" )
            {
                if ($category.Filter)
                {   
                    Write-Host "Has Filter" -ForegroundColor Green
                    $htmlTables += Get-PSSecurityEvent -Path $files -EventID $category.ID -UserPosition $category.UserPosition -Verbose |
                                   Where-Object { (& ([scriptblock]::Create($category.Filter)))} |
                                   ConvertTo-Html -Fragment -PreContent $category.Title
                }
                else
                {
                    Write-Host "No Filter" -ForegroundColor Green
                    $htmlTables += Get-PSSecurityEvent -Path $files -EventID $category.ID -UserPosition $category.UserPosition -Verbose |
                                   ConvertTo-Html -Fragment -PreContent $category.Title
                }
            }
            else
            {
                Write-Verbose "Skipping $($category.ID) for $report"
                continue #Do not process for this report
            }
        }

        Write-Verbose "`nPSAudit - New report - PSAudit-$report`n"
        ConvertTo-Html -Head $style -Body $htmlTables | Out-File .\PSAudit-$report.html
    }
} #End New-PSAudit


#Support function that will not be exported
Function Get-Folder($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
    #$foldername.rootfolder = "C:\"
    $foldername.ShowNewFolderButton = $false
    $foldername.Description = "PSAUDIT: Select folder for analysis"

    if($foldername.ShowDialog() -eq "OK")
    {
        $foldername.SelectedPath
    }

}

#Export-ModuleMember -Function Get-PSSecurityEvent, New-PSAudit