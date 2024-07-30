rd  /S /Q ".vs\Gleam-RT\v17\ipch"
del /S /Q ".vs\Gleam-RT\v17\Browse.VC.db"
del /S /Q ".vs\Gleam-RT\v17\Solution.VC.db"

rd /S /Q "Debug"
rd /S /Q "Release"
rd /S /Q "x64"
rd /S /Q "x86"

rd /S /Q "builder\builder_x64\Debug"
rd /S /Q "builder\builder_x64\Release"
rd /S /Q "builder\builder_x64\x64"
rd /S /Q "builder\builder_x64\x86"

rd /S /Q "builder\builder_x86\Debug"
rd /S /Q "builder\builder_x86\Release"
rd /S /Q "builder\builder_x86\x64"
rd /S /Q "builder\builder_x86\x86"

rd /S /Q "test\Debug"
rd /S /Q "test\Release"
rd /S /Q "test\x64"
rd /S /Q "test\x86"