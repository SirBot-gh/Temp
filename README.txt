PowerShell scripts posted as .txt.

  Sanitize-DeviceState.txt
  Split-PanBundle.txt

To run on Windows, rename to .ps1, then:

  powershell -NoProfile -ExecutionPolicy Bypass -File .\Sanitize-DeviceState.ps1 -InputPath <bundle> -OutputRoot <out>
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Split-PanBundle.ps1 -InputPath <bundle> -OutputRoot <out> -Redact
