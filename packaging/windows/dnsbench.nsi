!include "MUI2.nsh"

Name "DNSBench"
OutFile "dnsbench-setup.exe"
InstallDir "$LOCALAPPDATA\DNSBench"
RequestExecutionLevel user

!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Section "Install"
    SetOutPath "$INSTDIR"
    
    # Files to include
    File /r "dist/*.*"

    WriteUninstaller "$INSTDIR\Uninstall.exe"

    # Registry keys for "Add/Remove Programs" (User scope)
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSBench" "DisplayName" "DNSBench"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSBench" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSBench" "DisplayIcon" "$INSTDIR\dnsbench.exe"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSBench" "Publisher" "DNSBench"

    # Create shortcuts (User scope)
    CreateShortcut "$SMPROGRAMS\DNSBench.lnk" "$INSTDIR\dnsbench.exe"
    CreateShortcut "$DESKTOP\DNSBench.lnk" "$INSTDIR\dnsbench.exe"
SectionEnd

Section "Uninstall"
    Delete "$SMPROGRAMS\DNSBench.lnk"
    Delete "$DESKTOP\DNSBench.lnk"
    
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\DNSBench"
    
    RMDir /r "$INSTDIR"
SectionEnd

