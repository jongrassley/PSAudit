# PSAudit
PowerShell Module to help analyze Windows security logs.

This module still needs some work.  New-PSAudit needs parameters added and increased flexibility.  It was quickly created as a demo.

To use please save this in your PSModulePath.  The folder should be something like this, C:\Program Files\WindowsPowerShell\Modules\PSAudit.

Then in PowerShell cd to the path where you'd like your reports created.  Then run New-PSAudit.

Edit the audit\_categories.csv file to look for the particular events you are interested in.  Apply filters in this file, and give a description that will be included in the reports.  The Report field will group the events you are interested in.
