del /S /Q ".vs\ASM-Shelter\v17\ipch\AutoPCH"
del /S /Q ".vs\ASM-Shelter\v17\Browse.VC.db"

rd /S /Q "Debug"
rd /S /Q "Release"
rd /S /Q "x86"
rd /S /Q "x64"

rd /S /Q "builder\x86"
rd /S /Q "builder\x64"
rd /S /Q "builder\Debug"
rd /S /Q "builder\Release"

rd /S /Q "test\x86"
rd /S /Q "test\x64"
rd /S /Q "test\Debug"
rd /S /Q "test\Release"