del /S /Q ".vs\ASM-Shelter\v17\ipch\AutoPCH"
del /S /Q ".vs\ASM-Shelter\v17\Browse.VC.db"

rd /S /Q "Debug"
rd /S /Q "Release"
rd /S /Q "x86"
rd /S /Q "x64"

rd /S /Q "example\shelter\x86"
rd /S /Q "example\shelter\x64"
rd /S /Q "example\shelter\Debug"
rd /S /Q "example\shelter\Release"

rd /S /Q "test\x86"
rd /S /Q "test\x64"
rd /S /Q "test\Debug"
rd /S /Q "test\Release"