!include "MUI2.nsh"

Name "DNSBench"
OutFile "dnsbench-setup.exe"
InstallDir "$PROGRAMFILES64\DNSBench"
RequestExecutionLevel admin

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
    
    # Files to include (will be collected in the same directory as this script)
    File /r "dist/*.*"

    WriteUninstaller "$INSTDIR\Uninstall.exe"

    # Create shortcuts
    CreateShortcut "$SMPROGRAMS\DNSBench.lnk" "$INSTDIR\dnsbench.exe"
    CreateShortcut "$DESKTOP\DNSBench.lnk" "$INSTDIR\dnsbench.exe"
SectionEnd

Section "Uninstall"
    Delete "$SMPROGRAMS\DNSBench.lnk"
    Delete "$DESKTOP\DNSBench.lnk"
    
    RMDir /r "$INSTDIR"
SectionEnd
