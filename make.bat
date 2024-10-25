echo off
cls
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe -warn:4 -out:armada_1_ipx_query.exe armada_1_ipx_query.cs -r:ConsoleParameters.dll
pause
