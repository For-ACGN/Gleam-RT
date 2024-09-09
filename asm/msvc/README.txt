Copy From "Microsoft Visual Studio\VC\Tools\MSVC\14.40.33807\crt\src\i386"

Manually include these assembly files into the builder so that the compiler can
link in advance, thus ensuring that the layout of the entire shellcode is correct.

Specifically, place these functions before Argument_Stub instead of after Epilogue.
