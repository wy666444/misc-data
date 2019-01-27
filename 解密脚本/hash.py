from pwn import *
import hashlib
import string
from Crypto.Util.number import *
 
r = remote("202.120.7.206",'13337')
 
r.recvline()
str1 = r.recvline().strip()
print "condition: ", str1
 
prepend = str1[8:14]
sha_end = str1[len(str1)-15:len(str1)-10]
 
for i in string.letters + string.digits:
    for j in string.letters + string.digits:
        for k in string.letters + string.digits:
            for l in string.letters + string.digits:
                var = hashlib.sha256(prepend + i + j + k + l).hexdigest()[:5]
                if var == sha_end:
                    print "gotit!"
                    print "happening: ", r.recvline()
                    r.recvline()
                    r.sendline(i + j + k + l)
                    print r.recvuntil("want?\n\n")
                    r.interactive()
                    r.sendline("1")
                    print r.recvall()
                    exit()
                    break
print "Failed!"

