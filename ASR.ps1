# https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-attack-surface-reduction

# To exclude files and folders from ASR rules, use the following cmdlet:
# Add-MpPreference -AttackSurfaceReductionOnlyExclusions "<fully qualified path or resource>"
function Write-Friendly-Name {
    param (
        [string]$guid
    )
    switch ($guid) {
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" { $Prompt = "Block Adobe Reader from creating child processes" }
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" { $Prompt = "Block all Office applications from creating child processes" }
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" { $Prompt = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)" }
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" { $Prompt = "Block executable content from email client and webmail" }
        "01443614-cd74-433a-b99e-2ecdc07bfc25" { $Prompt = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion" }
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" { $Prompt = "Block execution of potentially obfuscated scripts" }
        "D3E037E1-3EB8-44C8-A917-57927947596D" { $Prompt = "Block JavaScript or VBScript from launching downloaded executable content" }
        "3B576869-A4EC-4529-8536-B80A7769E899" { $Prompt = "Block Office applications from creating executable content" }
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" { $Prompt = "Block Office applications from injecting code into other processes" }
        "26190899-1602-49e8-8b27-eb1d0a1ce869" { $Prompt = "Block Office communication application from creating child processes" }
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" { $Prompt = "Block persistence through WMI event subscription" }
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" { $Prompt = "Block process creations originating from PSExec and WMI commands" }
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" { $Prompt = "Block untrusted and unsigned processes that run from USB" }
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" { $Prompt = "Block Win32 API calls from Office macros" }
        "c1db55ab-c21a-4637-bb3f-a12568109d35" { $Prompt = "Use advanced protection against ransomware" }
    }
    return $Prompt
}  
  
function Set-Rule {
    param (
        [string]$guid
    )
    # PromptForChoice Args
    $Title = "Choose a setting for"
    $Choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No", "&AuditMode", "&Cancel")
    $Default = 3 #Cancel
     
    # Prompt for the choice
    $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Choices, $Default)
     
    # Action based on the choice
    switch ($Choice) {
        0 { 
            Set-MpPreference -AttackSurfaceReductionRules_Id $guid -AttackSurfaceReductionRules_Actions Enabled
            Write-Host "Enabled" -ForegroundColor Green
        }
        1 { 
            Set-MpPreference -AttackSurfaceReductionRules_Id $guid -AttackSurfaceReductionRules_Actions Disabled
            Write-Host "Disabled" -ForegroundColor Red 
        }
        2 { 
            Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions AuditMode
            Write-Host "Audit Mode" -ForegroundColor Magenta 
        }
        3 { Write-Host "Cancelled" -ForegroundColor Gray }
    }
    
}


Write-Host "Checking for elevated permissions..."
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
            [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."
    Break
}
else {
    Write-Host "Code is running as administrator" -ForegroundColor Green
}

$rules_guid = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", "01443614-cd74-433a-b99e-2ecdc07bfc25", "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", "D3E037E1-3EB8-44C8-A917-57927947596D", "3B576869-A4EC-4529-8536-B80A7769E899", "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", "26190899-1602-49e8-8b27-eb1d0a1ce869", "e6db77e5-3df2-4cf1-b95a-636979351e5b", "d1e49aac-8f56-4280-b9ba-993a6d77406c", "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", "c1db55ab-c21a-4637-bb3f-a12568109d35"
    
foreach ($guid in $rules_guid) {
    $Prompt = Write-Friendly-Name $guid
    Set-Rule $Prompt
}

Write-Host "All done"
