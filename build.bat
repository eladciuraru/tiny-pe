@echo off

set "ParentDir=%~dp0"
set "BuildDir=%ParentDir%build\"
set "SourceDir=%ParentDir%"


if not exist "%BuildDir%" (
    mkdir "%BuildDir%"
)

pushd %BuildDir%

nasm -f bin -O0 -I %SourceDir% -o %BuildDir%tiny_pe.exe %SourceDir%tiny_pe.asm

popd
