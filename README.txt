Temporary public copies of the PAN management-plane PowerShell scripts.
Source: gomsec-lab/pan-mgmt-assessment-toolkit @ df4dd73 (main).
These files are identical to the .ps1 scripts; only the extension is .txt.

  Sanitize-DeviceState.txt   <- Sanitize-DeviceState.ps1
  Split-PanBundle.txt        <- Split-PanBundle.ps1

To run on Windows, rename back to .ps1 (or copy), then:

  powershell -NoProfile -ExecutionPolicy Bypass -File .\Sanitize-DeviceState.ps1 -InputPath <bundle> -OutputRoot <out>
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Split-PanBundle.ps1 -InputPath <bundle> -OutputRoot <out> -Redact
