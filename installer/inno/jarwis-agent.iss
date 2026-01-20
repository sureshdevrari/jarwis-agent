; Jarwis Security Agent - Inno Setup Script
; Professional Windows Installer

#define MyAppName "Jarwis Security Agent"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "Jarwis Security"
#define MyAppURL "https://jarwis.ai"
#define MyAppExeName "jarwis-agent.exe"
#define MyAppServiceName "JarwisAgent"

[Setup]
; Basic info
AppId={{8A4B3C2D-1E2F-3A4B-5C6D-7E8F9A0B1C2D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/support
AppUpdatesURL={#MyAppURL}/downloads
DefaultDirName={autopf}\Jarwis\Agent
DefaultGroupName=Jarwis Security
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE.rtf
OutputDir=..\..\dist\installer
OutputBaseFilename=JarwisAgentSetup-{#MyAppVersion}
SetupIconFile=..\assets\icons\jarwis-agent.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

; Visual settings
WizardImageFile=..\assets\bitmaps\wizard_large.bmp
WizardSmallImageFile=..\assets\bitmaps\wizard_small.bmp
SetupLogging=yes

; Version info
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup
VersionInfoTextVersion={#MyAppVersion}
VersionInfoCopyright=Copyright (C) 2024-2026 {#MyAppPublisher}
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

; Uninstall settings
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel1=Welcome to the [name] Setup Wizard
WelcomeLabel2=This will install [name/ver] on your computer.%n%nThe agent provides real-time security monitoring, vulnerability scanning, and integration with the Jarwis Security Platform.%n%nIt is recommended that you close all other applications before continuing.

[Types]
Name: "full"; Description: "Full installation (recommended)"
Name: "compact"; Description: "Compact installation (agent only)"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "main"; Description: "Jarwis Agent Core"; Types: full compact custom; Flags: fixed
Name: "service"; Description: "Windows Service (auto-start at boot)"; Types: full custom
Name: "tray"; Description: "System Tray Application"; Types: full custom
Name: "shortcuts"; Description: "Desktop and Start Menu shortcuts"; Types: full custom

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Components: shortcuts
Name: "startupicon"; Description: "Start system tray at Windows startup"; GroupDescription: "Startup:"; Components: tray

[Files]
; Main executable
Source: "..\..\dist\jarwis-agent.exe"; DestDir: "{app}"; Flags: ignoreversion; Components: main

; System tray app
Source: "..\..\dist\jarwis-tray.exe"; DestDir: "{app}"; Flags: ignoreversion; Components: tray

; Configuration
Source: "..\..\config\config.yaml"; DestDir: "{app}\config"; Flags: ignoreversion onlyifdoesntexist; Components: main

; Assets
Source: "..\assets\icons\jarwis-agent.ico"; DestDir: "{app}"; Flags: ignoreversion; Components: main
Source: "..\..\assets\logos\PNG-01.png"; DestDir: "{app}\assets"; Flags: ignoreversion; Components: main

[Dirs]
Name: "{app}\logs"; Components: main
Name: "{app}\data"; Components: main
Name: "{app}\config"; Components: main

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Components: shortcuts
Name: "{group}\{#MyAppName} Configuration"; Filename: "{app}\config\config.yaml"; Components: shortcuts
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; Components: shortcuts
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userstartup}\Jarwis Agent Tray"; Filename: "{app}\jarwis-tray.exe"; Tasks: startupicon

[Registry]
; App paths
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyAppExeName}"; ValueType: string; ValueName: "Path"; ValueData: "{app}"; Flags: uninsdeletekey

; Jarwis settings
Root: HKLM; Subkey: "SOFTWARE\Jarwis\Agent"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Jarwis\Agent"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"; Flags: uninsdeletekey

[Run]
; Install service
Filename: "{sys}\sc.exe"; Parameters: "create {#MyAppServiceName} binPath=""{app}\{#MyAppExeName} --service"" start=auto DisplayName=""{#MyAppName}"""; Flags: runhidden; Components: service; StatusMsg: "Installing Windows service..."
Filename: "{sys}\sc.exe"; Parameters: "description {#MyAppServiceName} ""Jarwis Security Agent - Endpoint protection and security scanning service"""; Flags: runhidden; Components: service
Filename: "{sys}\sc.exe"; Parameters: "start {#MyAppServiceName}"; Flags: runhidden; Components: service; StatusMsg: "Starting Jarwis Agent service..."

; Launch options
Filename: "{app}\jarwis-tray.exe"; Description: "Launch Jarwis Agent system tray"; Flags: nowait postinstall skipifsilent; Components: tray

[UninstallRun]
; Stop and remove service
Filename: "{sys}\sc.exe"; Parameters: "stop {#MyAppServiceName}"; Flags: runhidden; Components: service
Filename: "{sys}\sc.exe"; Parameters: "delete {#MyAppServiceName}"; Flags: runhidden; Components: service

[Code]
var
  ServerPage: TInputQueryWizardPage;
  ActivationPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  // Server configuration page
  ServerPage := CreateInputQueryPage(wpSelectComponents,
    'Server Configuration',
    'Configure the connection to your Jarwis server',
    'Please enter the Jarwis server URL:');
  ServerPage.Add('Server URL:', False);
  ServerPage.Values[0] := 'https://app.jarwis.ai';
  
  // Activation page
  ActivationPage := CreateInputQueryPage(ServerPage.ID,
    'Activation',
    'Activate your Jarwis Agent',
    'Enter your activation key (you can also activate later from the dashboard):');
  ActivationPage.Add('Activation Key:', False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigPath: string;
  ConfigContent: TStringList;
begin
  if CurStep = ssPostInstall then
  begin
    // Update config with server URL
    ConfigPath := ExpandConstant('{app}\config\config.yaml');
    if FileExists(ConfigPath) then
    begin
      ConfigContent := TStringList.Create;
      try
        ConfigContent.LoadFromFile(ConfigPath);
        // Add server URL to config if not empty
        if ServerPage.Values[0] <> '' then
        begin
          ConfigContent.Add('');
          ConfigContent.Add('# Server configuration (set by installer)');
          ConfigContent.Add('server_url: ' + ServerPage.Values[0]);
        end;
        ConfigContent.SaveToFile(ConfigPath);
      finally
        ConfigContent.Free;
      end;
    end;
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  // Check for existing installation
  if RegKeyExists(HKLM, 'SOFTWARE\Jarwis\Agent') then
  begin
    if MsgBox('A previous version of Jarwis Agent is installed. Would you like to upgrade?', 
              mbConfirmation, MB_YESNO) = IDNO then
      Result := False;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    // Stop tray application
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM jarwis-tray.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
