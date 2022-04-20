Import-Module ".\ConvertTo-Shellcode.ps1"; 

Get-ChildItem Public -filter *.dll|%{$bytes = ConvertTo-Shellcode -ClearHeader -File $_.FullName; [io.file]::WriteAllBytes( "Public/$($_.BaseName)_Shellcode.bin", $bytes) } 

Get-ChildItem Public -filter *.dll|%{$b = gc $_.FullName -Encoding Byte; [System.Convert]::ToBase64String($b)|out-file "Public/$($_.BaseName)_dll.b64" -encoding ascii } 

Get-ChildItem Public -filter *.bin|%{$b = gc $_.FullName -Encoding Byte; [System.Convert]::ToBase64String($b)|out-file "Public/$($_.BaseName).b64" -encoding ascii } 

