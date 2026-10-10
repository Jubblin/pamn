; Npcap's licence forbids bundling its installer, so just point the user at the official download.
!macro NSIS_HOOK_POSTINSTALL
  ; nmap.exe is 32-bit: install the bundled x86 VC++ runtime silently if it is missing.
  SetRegView 32
  ReadRegDWORD $1 HKLM "SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x86" "Installed"
  IntCmp $1 1 pamn_vc_done 0 0
  IfFileExists "$INSTDIR\nmap\vc_redist.x86.exe" 0 pamn_vc_done
  ExecWait '"$INSTDIR\nmap\vc_redist.x86.exe" /install /quiet /norestart' $2
  pamn_vc_done:
  SetRegView 64
  ReadRegStr $0 HKLM "SOFTWARE\Npcap" ""
  StrCmp $0 "" 0 pamn_npcap_done
  MessageBox MB_YESNO "Pamn needs the free Npcap network driver to scan. Open the Npcap download page now?" /SD IDNO IDNO pamn_npcap_done
  ExecShell "open" "https://npcap.com/#download"
  pamn_npcap_done:
!macroend
