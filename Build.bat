@echo off

echo ========== initialize Visual Studio environment ==========
call "%VisualStudio%\VC\Auxiliary\Build\vcvars64.bat"

echo ================= clean builder old files ================
rd /S /Q "builder\Release"
rd /S /Q "builder\x64"
rd /S /Q "Release"
rd /S /Q "x64"

echo ==================== generate builder ====================
MSbuild Gleam-RT.sln /t:builder /p:Configuration=Release /p:Platform=x64
MSbuild Gleam-RT.sln /t:builder /p:Configuration=Release /p:Platform=x86

echo ================ extract runtime shellcode ===============
cd builder
"..\x64\Release\builder.exe"
"..\Release\builder.exe"

echo ================ generate assembly module ================
cd ..\script
call asm_mod.bat
cd ..

echo ==========================================================
echo                  build shellcode finish!
echo ==========================================================
