@echo off
set basedir=%0/..
cl /O2 %basedir%/tweetnacl.c /c /Fo%basedir%/tweetnacl-%1.obj
lib %basedir%/tweetnacl-%1.obj -OUT:%basedir%/tweetnacl-%1.lib