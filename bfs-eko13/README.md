Quick write-up for Blue Frost Security's EkoParty 13 exploit challenge.

The binary is quite straightforward, and after a quick handshake it goes into the vulnerable function:

```C
int __fastcall vuln_func(SOCKET a1)
{
  char *alloc; // ST20_8@5
  unsigned int v3; // [rsp+30h] [rbp-128h]@1
  int smashsize; // [rsp+30h] [rbp-128h]@5
  recv_t buf; // [rsp+34h] [rbp-124h]@1
  char Dst[256]; // [rsp+40h] [rbp-118h]@5
  SOCKET socket; // [rsp+160h] [rbp+8h]@1

  socket = a1;
  printf(Format);
  v3 = recv(socket, (char *)&buf, 4, 0);
  if ( v3 == -1 )
    return printf("  [-] Client data error\n");
  if ( v3 < 4 )
    return printf("  [-] Bad size\n");
  alloc = (char *)malloc(buf.size);
  smashsize = recv(socket, alloc, buf.size, 0);
  printf(" [+] Data received: %i bytes\n", (unsigned int)(smashsize + 4));
  memcpy(Dst, alloc, buf.size);                 // We get a pretty arbitrary stack overflow here
  free(alloc);
  if ( buf.size != smashsize )
    return printf("  [-] Invalid size\n");
  functions[(unsigned __int64)(unsigned __int8)buf.index](Dst);
  return send(socket, Dst, smashsize + 1, 0);   // Data gets back, but including some more data
}
```

As you can see int he comments, we get one extra byte than we smash. I used this to leak 80 bytes of stack, which include:

* The stack cookie 
* The return address
* The original socket value
* A stack address

The leaked stack cookie is used to bypass the checks, the return address to adjust our ROP chain, and the socket value for process continuation.

I first used a simple ROPChain that would setup ecx and call system, but then decided to go another route:

* Use a write gadget to backdoor the functions[] table with system()
* Return to the main loop with the correct socket value

After this, I can create new connections and execute arbitrary commands by passing the function id of the backdoored function and my command in the payload buffer.

I originally used a ```pop rsp; ret``` gadget to pivot the stack to the beginning of our buffer and prevent smashing too much stack, and  this is what I submitted to the challenge. 

However, afterwards I realized that the offset from the leaked stack address to the buffer differes between my Win7 test machines and my Win10 VM, so I ended up fixing my exploit to place the ROP chain at the end of the buffer. This makes the exploit work both on Win10 and Win7.

One note though: when trying to make the exploit work on Win10 I had crashes within ```strlen()```. This was caused by a misaligned stack, so just be careful to always have your stacks aligned on 16-byte on the x64 platform as the compiler may assume this when emitting certain instructions!

See bfs.py for the exploit. I've tested it on a couple Win7 machines and ONE Win10 machine, so YMMV.
