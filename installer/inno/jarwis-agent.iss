; =============================================================================
; Jarwis Security Agent - Inno Setup Script
; =============================================================================
;
; Professional Windows installer with:
; - Custom branding and wizard images
; - License agreement
; - Installation path selection
; - Feature selection
; - Windows service installation
; - System tray application
; - Start menu shortcuts
; - Uninstaller
;
; Build: iscc jarwis-agent.iss
;
; Requirements:
; - Inno Setup 6.2+ (https://jrsoftware.org/isinfo.php)
; - Inno Setup Preprocessor
;
; =============================================================================

#define MyAppName "Jarwis Security Agent"
#define MyAppVersion "2.1.0"
#define MyAppPublisher "Jarwis Security"
#define MyAppURL "https://jarwis.io"
#define MyAppExeName "jarwis-agent.exe"
#define MyAppServiceName "JarwisAgent"

[Setup]
; Application identity
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/support
AppUpdatesURL={#MyAppURL}/download

; Version info
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=Jarwis Security Testing Agent
VersionInfoCopyright=Copyright © 2026 Jarwis Security
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

; Installation paths
DefaultDirName={autopf}\Jarwis Agent
DefaultGroupName=Jarwis Security
DisableProgramGroupPage=yes
AllowNoIcons=yes

; Output settings
OutputDir=..\..\dist\inno
OutputBaseFilename=jarwis-agent-{#MyAppVersion}-setup
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes

; Installer appearance
SetupIconFile=..\assets\icons\jarwis-agent.ico
WizardStyle=modern
WizardSizePercent=100
WizardImageFile=..\assets\bitmaps\wizard_large.bmp
WizardSmallImageFile=..\assets\bitmaps\wizard_small.bmp

; License
LicenseFile=..\LICENSE.rtf

; Privileges
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; Signing (uncomment for production)
; SignTool=signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /a $f
; SignedUninstaller=yes

; Uninstaller
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
CreateUninstallRegKey=yes

; Architecture
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible

; Miscellaneous
DisableWelcomePage=no
DisableDirPage=no
DisableReadyPage=no
ShowLanguageDialog=no
UsePreviousAppDir=yes
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel1=Welcome to the {#MyAppName} Setup Wizard
WelcomeLabel2=This will install {#MyAppName} version {#MyAppVersion} on your computer.%n%nThe agent enables comprehensive security testing including:%n• Web Application Security Testing%n• Mobile Application Analysis%n• Network Vulnerability Scanning%n• Cloud Security Assessment%n• Static Code Analysis (SAST)%n%nClick Next to continue.
FinishedHeadingLabel=Completing the {#MyAppName} Setup
FinishedLabel={#MyAppName} has been installed on your computer.%n%nThe agent is now running and will automatically connect to the Jarwis server.

[Types]
Name: "full"; Description: "Full installation (all features)"
Name: "compact"; Description: "Compact installation (minimal features)"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "core"; Description: "Core Agent"; Types: full compact custom; Flags: fixed
Name: "web"; Description: "Web Application Security Testing"; Types: full
Name: "mobile"; Description: "Mobile Application Analysis"; Types: full
Name: "network"; Description: "Network Security Scanning"; Types: full
Name: "cloud"; Description: "Cloud Security Assessment"; Types: full custom
Name: "sast"; Description: "Static Code Analysis (SAST)"; Types: full
Name: "tray"; Description: "System Tray Application"; Types: full compact custom

[Tasks]
Name: "installservice"; Description: "Install as Windows Service"; GroupDescription: "Service Options:"; Flags: checkedonce
Name: "autostart"; Description: "Start agent after installation"; GroupDescription: "Service Options:"; Flags: checkedonce
Name: "startmenu"; Description: "Create Start Menu shortcuts"; GroupDescription: "Shortcuts:"
Name: "desktopicon"; Description: "Create Desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
; Core files
Source: "..\..\dist\windows\x64\jarwis-agent.exe"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "..\..\dist\windows\x64\config.yaml"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "..\LICENSE.rtf"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion; Components: core

; System tray application
Source: "..\..\dist\windows\x64\jarwis-tray.exe"; DestDir: "{app}"; Flags: ignoreversion; Components: tray

; Additional files would be added here based on components

[Dirs]
Name: "{app}\logs"; Permissions: users-modify
Name: "{app}\data"; Permissions: users-modify

[Icons]
; Start menu
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--status"; Tasks: startmenu
Name: "{group}\Jarwis Dashboard"; Filename: "https://jarwis.io/dashboard"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: startmenu
Name: "{group}\Documentation"; Filename: "https://jarwis.io/docs"; Tasks: startmenu
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"; Tasks: startmenu

; Desktop
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--status"; Tasks: desktopicon

; Startup (for tray app)
Name: "{autostartup}\Jarwis Agent Tray"; Filename: "{app}\jarwis-tray.exe"; Components: tray

[Registry]
; Installation info
Root: HKLM; Subkey: "SOFTWARE\Jarwis\Agent"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"
Root: HKLM; Subkey: "SOFTWARE\Jarwis\Agent"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"
Root: HKLM; Subkey: "SOFTWARE\Jarwis\Agent"; ValueType: string; ValueName: "ServerUrl"; ValueData: "{code:GetServerUrl}"
Root: HKLM; Subkey: "SOFTWARE\Jarwis\Agent"; ValueType: string; ValueName: "ActivationKey"; ValueData: "{code:GetActivationKey}"

; Add to PATH (optional)
; Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}')

[Run]
; Install Windows service
Filename: "sc.exe"; Parameters: "create {#MyAppServiceName} binPath= ""{app}\{#MyAppExeName}"" --service DisplayName= ""Jarwis Security Agent"" start= auto"; StatusMsg: "Installing Windows service..."; Flags: runhidden; Tasks: installservice
Filename: "sc.exe"; Parameters: "description {#MyAppServiceName} ""Background agent for Jarwis security testing platform"""; Flags: runhidden; Tasks: installservice
Filename: "sc.exe"; Parameters: "failure {#MyAppServiceName} reset= 86400 actions= restart/60000/restart/60000/restart/60000"; Flags: runhidden; Tasks: installservice

; Start service
Filename: "sc.exe"; Parameters: "start {#MyAppServiceName}"; StatusMsg: "Starting agent service..."; Flags: runhidden; Tasks: installservice and autostart

; Start tray app
Filename: "{app}\jarwis-tray.exe"; Description: "Launch system tray application"; Flags: nowait postinstall skipifsilent; Components: tray

; Open dashboard
Filename: "https://jarwis.io/dashboard"; Description: "Open Jarwis Dashboard"; Flags: shellexec nowait postinstall skipifsilent unchecked

[UninstallRun]
; Stop and remove service
Filename: "sc.exe"; Parameters: "stop {#MyAppServiceName}"; Flags: runhidden
Filename: "sc.exe"; Parameters: "delete {#MyAppServiceName}"; Flags: runhidden

; Kill tray app
Filename: "taskkill.exe"; Parameters: "/F /IM jarwis-tray.exe"; Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\data"

[Code]
var
  ServerUrlPage: TInputQueryWizardPage;
  ActivationKeyPage: TInputQueryWizardPage;
  ServerUrl: String;
  ActivationKey: String;

procedure InitializeWizard();
begin
  // Server URL page
  ServerUrlPage := CreateInputQueryPage(wpSelectTasks,
    'Server Configuration',
    'Configure the connection to your Jarwis server.',
    'Enter the URL of your Jarwis server:');
  ServerUrlPage.Add('Server URL:', False);
  ServerUrlPage.Values[0] := 'wss://jarwis.io/ws/agent';

  // Activation Key page
  ActivationKeyPage := CreateInputQueryPage(ServerUrlPage.ID,
    'Activation Key',
    'Enter your activation key (optional).',
    'You can find your activation key in the Jarwis Dashboard under Settings > Agent.');
  ActivationKeyPage.Add('Activation Key:', False);
  ActivationKeyPage.Values[0] := '';
end;

function GetServerUrl(Param: String): String;
begin
  Result := ServerUrlPage.Values[0];
end;

function GetActivationKey(Param: String): String;
begin
  Result := ActivationKeyPage.Values[0];
end;

function NeedsAddPath(Param: String): Boolean;
var
  OrigPath: String;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  // Look for the path with leading and trailing semicolons
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigFile: String;
  ConfigContent: String;
begin
  if CurStep = ssPostInstall then begin
    // Create agent configuration file
    ConfigFile := ExpandConstant('{app}\agent-config.yaml');
    ConfigContent := '# Jarwis Agent Configuration' + #13#10 +
                     '# Generated by Setup Wizard' + #13#10 +
                     #13#10 +
                     'server:' + #13#10 +
                     '  url: "' + ServerUrlPage.Values[0] + '"' + #13#10 +
                     '  reconnect_interval: 30' + #13#10 +
                     '  heartbeat_interval: 15' + #13#10 +
                     #13#10 +
                     'agent:' + #13#10 +
                     '  activation_key: "' + ActivationKeyPage.Values[0] + '"' + #13#10 +
                     '  auto_start: true' + #13#10 +
                     #13#10 +
                     'features:' + #13#10 +
                     '  web_scanning: ' + BoolToStr(IsComponentSelected('web')) + #13#10 +
                     '  mobile_scanning: ' + BoolToStr(IsComponentSelected('mobile')) + #13#10 +
                     '  network_scanning: ' + BoolToStr(IsComponentSelected('network')) + #13#10 +
                     '  cloud_scanning: ' + BoolToStr(IsComponentSelected('cloud')) + #13#10 +
                     '  sast_scanning: ' + BoolToStr(IsComponentSelected('sast')) + #13#10 +
                     #13#10 +
                     'logging:' + #13#10 +
                     '  level: INFO' + #13#10 +
                     '  file: logs/agent.log' + #13#10 +
                     '  max_size_mb: 50' + #13#10 +
                     '  backup_count: 5' + #13#10;
    SaveStringToFile(ConfigFile, ConfigContent, False);
  end;
end;

function BoolToStr(Value: Boolean): String;
begin
  if Value then
    Result := 'true'
  else
    Result := 'false';
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  // Stop existing service if running
  Exec('sc.exe', 'stop JarwisAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  
  // Kill any running tray apps
  Exec('taskkill.exe', '/F /IM jarwis-tray.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  
  // Small delay to ensure processes are stopped
  Sleep(1000);
  
  Result := '';
end;
