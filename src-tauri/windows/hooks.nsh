; Npcap's licence forbids bundling its installer, so just point the user at the official download.
!macro NSIS_HOOK_POSTINSTALL
  SetRegView 64
  ReadRegStr $0 HKLM "SOFTWARE\Npcap" ""
  StrCmp $0 "" 0 pamn_npcap_done
  MessageBox MB_YESNO "Pamn needs the free Npcap network driver to scan. Open the Npcap download page now?" /SD IDNO IDNO pamn_npcap_done
  ExecShell "open" "https://npcap.com/#download"
  pamn_npcap_done:
!macroend
