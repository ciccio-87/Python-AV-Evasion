from ctypes import *
import thread

libc = CDLL('libc.so.6')

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


shellcode = "INSERT SHELLCODE HERE"

memorywithshell = executable_code(shellcode)
shell = cast(memorywithshell, CFUNCTYPE(c_void_p))
#shell()
#print 'starting thread'
thread.start_new_thread(shell(),())
