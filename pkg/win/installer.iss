#ifndef InstallerSourceDir
  #define InstallerSourceDir "..\build\installer_dir"
#endif

[Setup]
AppId=PC Bio Unlock
AppName=PulseUnlock
AppVerName=PulseUnlock
AppVersion={#GetEnv('APP_VERSION')}
VersionInfoVersion={#GetEnv('APP_VERSION')}
WizardStyle=modern
DefaultDirName={autopf}\PulseUnlock
DefaultGroupName=PulseUnlock
UsePreviousAppDir=yes
UsePreviousGroup=no
UninstallDisplayIcon={app}\pcbu_desktop.exe
Compression=lzma2
SolidCompression=yes
OutputDir=..\build\
PrivilegesRequired=admin
ArchitecturesAllowed={#GetEnv('ARCH')}
ArchitecturesInstallIn64BitMode={#GetEnv('ARCH')}
;ArchitecturesAllowed=arm64
;ArchitecturesInstallIn64BitMode=arm64

[Files]
; Replace our same-version test builds; retain version checks for third-party files.
Source: "{#InstallerSourceDir}\pcbu_desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#InstallerSourceDir}\pcbu_elevator.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#InstallerSourceDir}\*"; DestDir: "{app}"; Excludes: "pcbu_desktop.exe,pcbu_elevator.exe,pcbu_storage_test.exe"; Flags: recursesubdirs

[InstallDelete]
Type: filesandordirs; Name: "{commonprograms}\PC Bio Unlock"
Type: filesandordirs; Name: "{userprograms}\PC Bio Unlock"

[Icons]
Name: "{group}\PulseUnlock"; Filename: "{app}\pcbu_desktop.exe"

[Run]
Filename: "{app}\pcbu_desktop.exe"; Description: "Launch PulseUnlock"; Verb: runas; Flags: postinstall nowait skipifsilent runascurrentuser shellexec

[Code]
const
  VCRedistURL_x64 = 'https://aka.ms/vs/17/release/vc_redist.x64.exe';
  VCRedistURL_arm64 = 'https://aka.ms/vs/17/release/vc_redist.arm64.exe';
var
  DownloadPage: TDownloadWizardPage;

function InstallX64: Boolean;
begin
  Result := Is64BitInstallMode and (ProcessorArchitecture = paX64);
end;

function InstallARM64: Boolean;
begin
  Result := Is64BitInstallMode and (ProcessorArchitecture = paARM64);
end;

procedure InstallVCRedist(const FileName: string);
var
  ResultCode: Integer;
begin
  if ShellExec('runas', FileName, '/install /quiet /norestart', '', SW_SHOW, ewWaitUntilTerminated, ResultCode) then
  begin
    if (ResultCode <> 0) and (ResultCode <> 1638) and (ResultCode <> 3010) then
      RaiseException('Microsoft runtime installation failed. Exit code: ' + IntToStr(ResultCode));
    Log('vcredist installation completed.');
  end
  else
  begin
    RaiseException('Failed to install vcredist. Error code: ' + IntToStr(ResultCode));
  end;
end;

function OnDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  if Progress = ProgressMax then begin
    Log(Format('Successfully downloaded file to %s', [Format('%s\%s', [ExpandConstant('{tmp}'), FileName])]));
  end;
  Result := True;
end;

procedure InitializeWizard;
begin
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), SetupMessage(msgPreparingDesc), @OnDownloadProgress);
end;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := False;
  if not UninstallSilent then
    if MsgBox('Remove PulseUnlock and unregister its Windows sign-in provider? Local pairings and settings will be kept.', mbConfirmation, MB_YESNO) <> IDYES then
      Exit;
  if not ShellExec('runas', ExpandConstant('{app}\pcbu_elevator.exe'), '--uninstall-system', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    SuppressibleMsgBox('System cleanup could not start (stage: helper launch). Uninstall was cancelled; the application and helper have been kept.', mbCriticalError, MB_OK, IDOK);
    Exit;
  end;
  if ResultCode <> 0 then
  begin
    SuppressibleMsgBox('System cleanup failed (stage: REMOVE_PROVIDER or REMOVE_FIREWALL; helper exit code ' + IntToStr(ResultCode) + '). Uninstall was cancelled; the application and helper have been kept.', mbCriticalError, MB_OK, IDOK);
    Exit;
  end;
  Result := True;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  if CurPageID = wpReady then begin
    DownloadPage.Clear;
    if InstallX64() then begin
      DownloadPage.Add(VCRedistURL_x64, 'vcredist.exe', '');
    end else begin
      DownloadPage.Add(VCRedistURL_arm64, 'vcredist.exe', '');
    end;
    DownloadPage.Show;
    try
      try
        DownloadPage.Download;
        InstallVCRedist(Format('%s\vcredist.exe', [ExpandConstant('{tmp}')]));
        Result := True;
      except
        SuppressibleMsgBox(AddPeriod(GetExceptionMessage), mbCriticalError, MB_OK, IDOK);
        Result := False;
      end;
    finally
      DownloadPage.Hide;
    end;
  end else
    Result := True;
end;
