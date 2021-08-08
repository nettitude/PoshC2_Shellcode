copy mimikatz\x64\powerkatz.dll SharpSploit\SharpSploit\Resources\powerkatz_x64.dll
copy mimikatz\win32\powerkatz.dll SharpSploit\SharpSploit\Resources\powerkatz_x86.dll

powershell -ep bypass -c ". '.\Out-CompressedDll.ps1';Out-CompressedDll -FilePath mimikatz\x64\powerkatz.dll -Out SharpSploit\SharpSploit\Resources\powerkatz_x64.dll.comp"
powershell -ep bypass -c ". '.\Out-CompressedDll.ps1'; Out-CompressedDll -FilePath mimikatz\win32\powerkatz.dll -Out SharpSploit\SharpSploit\Resources\powerkatz_x86.dll.comp"