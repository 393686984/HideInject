set "projectpath=%cd%"
cd ../
set "preProjectpath=%cd%"
cd %projectpath%
set "SignFullPath=%preProjectpath%/x64/Release/Test.dll"
Build.exe %SignFullPath%

