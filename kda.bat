@echo off
cd %~dp0
SET _NT_SYMBOL_PATH=srv*c:\Symbols*http://msdl.microsoft.com/download/symbols;%~dp0
d:\msdbg\kd.exe -z "pmpsimulator.exe.3944(pmpsimulator.exe.3944-20181110_080230000).dmp" -c "ld *;!peb;!dlls;!analyze -v;!runaway 4;!uniqstack;q"

:: all stacks instead of unique-stacks
:: ~* k
