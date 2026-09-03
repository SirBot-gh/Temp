PowerShell scripts posted as .txt.

  Sanitize-DeviceState.txt
  Split-PanBundle.txt
  Split-PanRulebase.txt
  Build-CombinedConfig.txt

To run on Windows, rename to .ps1, then:

  powershell -NoProfile -ExecutionPolicy Bypass -File .\Sanitize-DeviceState.ps1 -InputPath <bundle> -OutputRoot <out>
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Split-PanBundle.ps1 -InputPath <bundle> -OutputRoot <out> -Redact
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Split-PanRulebase.ps1 -InputPath <rulebase.xml> -OutputPath <out>
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Build-CombinedConfig.ps1 -InputPath <bundle.tgz> -OutputPath <out>
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Build-CombinedConfig.ps1 -InputPath <bundle.tgz> -OutputPath <out> -Xml
