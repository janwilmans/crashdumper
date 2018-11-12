@echo off
cd %~dp0
:: note: passing the current path as extra symbol path to the analyse.txt 
d:\msdbg\windbg.exe -z "pmpsimulator.exe.3944(pmpsimulator.exe.3944-20181110_080230000).dmp" -c"$<analyse.txt" -loga output.txt