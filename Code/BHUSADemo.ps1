# Clear Sysmon and WMI activity event logs
wevtutil cl Microsoft-Windows-Sysmon/Operational
wevtutil cl Microsoft-Windows-WMI-Activity/Operational

# Show WMI events being captured in Sysmon
.\Sysmon64.exe -c

# Load WMI evasion code
. .\WmiEventConsumerClassDerivation.ps1

# Create ActiveScriptEventConsumer class in root/Foo namespace
New-ActiveScriptEventConsumerClass -Namespace Foo -ClassName NotAnActiveScriptEventConsumer

New-Item C:\Windows\Temp\wmifiledrop.txt

# Execute WMIEvasionDemo.ps1
. .\WMIEvasionDemo.ps1

# Observe WMI persistence execution
Get-Content C:\Windows\Temp\wmifiledrop.txt -Wait

# Retrieve FilterToConsumerBinding events
Get-WinEvent -FilterHashTable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 21 }

# Generic Win10 detection
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WMI-Activity/Operational'; Id = 5861 } |
    Select -ExpandProperty Message

<# Cleanup
# Remove persistence
$TargetNamespace = 'root/Foo'
Get-WmiObject -Namespace $TargetNamespace -Class __IntervalTimerInstruction | Remove-WmiObject
Get-WmiObject -Namespace $TargetNamespace -Class __FilterToConsumerBinding | Remove-WmiObject
Get-WmiObject -Namespace $TargetNamespace -Class NotAnActiveScriptEventConsumer | Remove-WmiObject
Get-WmiObject -Namespace $TargetNamespace -Class __EventFilter | Remove-WmiObject

# Remove ActiveScriptEventConsumer definition/registration 
$NewActiveScriptEventConsumer = Get-WmiObject -Namespace $TargetNamespace -Class Meta_Class -Filter "__CLASS = 'NotAnActiveScriptEventConsumer'"
$NewActiveScriptEventConsumer.Delete()

Get-CimInstance -Namespace $TargetNamespace -ClassName __Win32Provider -Filter 'Name = "NotAnActiveScriptEventConsumer"' | Remove-CimInstance
Get-CimInstance -Namespace root -ClassName __NAMESPACE -Filter 'Name = "Foo"' | Remove-CimInstance

rm C:\Windows\Temp\wmifiledrop.txt
#>

