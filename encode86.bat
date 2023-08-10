set "projectpath=%cd%"
cd ../
set "preProjectpath=%cd%"
cd %projectpath%
set "SignFullPath=%preProjectpath%/Release/Test.dll"
Build.exe %SignFullPath%

