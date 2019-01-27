import hashlib
import random
import time
import socket
from factordb.factordb import FactorDB
from wiener_attack import *
from pwn import *

def gcd(a,b):
    while a!=0:
        a,b = b%a,a
    return b

def findModReverse(a,m):
    if gcd(a,m)!=1:
        return None
    u1,u2,u3 = 1,0,a
    v1,v2,v3 = 0,1,m
    while v3!=0:
        q = u3//v3
        v1,v2,v3,u1,u2,u3 = (u1-q*v1),(u2-q*v2),(u3-q*v3),v1,v2,v3
    return u1%m

def solve(res):
    x=[0x00,0x00,0x00]
    while 1:
        #x=chr(random.randint(0,0xff))+chr(random.randint(0,0xff))+chr(random.randint(0,0x1f))
        if x[2]==0x1f:
            x[1]=x[1]+1
            x[2]=0x00
        else: 
            x[2]=x[2]+1
        
        if x[1]==0xff:
            x[0]=x[0]+1
            x[1]=0x00
            x[2]=0x00


        if x[0]==0xff:
            break
        #if hashlib.sha256(x).hexdigest()[0:8]==res:
        #    print x.encode('hex')
        #    break
        #time.sleep(0.01)

        y=chr(x[0])+chr(x[1])+chr(x[2])
        if hashlib.sha256(y).hexdigest()[0:8]==res:
            print y.encode('hex')
            return y.encode('hex')
            break

def rsa_decrypt(n,c,e):
        f = FactorDB(n)
        print ">>>>>>>------- integer factorization --------<<<<<<<<"
        f.connect()
        print ">>>>>>>------- factorization result --------<<<<<<<<<"
        print f.get_factor_list()
        try:
            f.get_factor_list()[1]
        except:
            return 1
        fi=(f.get_factor_list()[0]-1)*(f.get_factor_list()[1]-1)
        d=findModReverse(e,fi)
        m=pow(c,d,n)
        return m

def netcat(hostname, port, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))
    #s.sendall(content)
    #s.shutdown(socket.SHUT_WR)
    count=0
    while 1:
        count+=1
        data = s.recv(2048)
        #time.sleep(1)
        if data == "":
            #break
            #raw_input()
            continue
        print "count:",count
        print "--------data start-------->>>count:",count
        print data
        print "--------data end----------"

        if count==1:
            s.send("icq9119c54dcf8888f7fb2ce395fa677")
            #print(data[-21:-27]);


        if count==2:
            #time.sleep(5)
            #print("--------------")
            #print data
            print("------solving--------")
            print(data[185:193])
            res=(data[185:193])
            send_res=solve(res)
            s.send(send_res)
            #print("-------solved-------")
        time.sleep(1)

        if count==3:
            n=data[65:131]
            print "n:",n
            e=data[136:143]
            print "e:",e
            c=data[148:214]
            print "c:",c
            n=int(n,16)
            e=int(e,16)
            c=int(c,16)
            
            # first, extract N
            m=rsa_decrypt(n,c,e)
            print "m:",hex(m).replace("L","")
            time.sleep(1)
            s.send(hex(m).replace("L",""))
                
            print "send done"

        if count==5:
            data_s=data.split('\n')
            #print ">>>>>>>>splited<<<<<<<<<"
            #print data
            n=data_s[1][4:]
            print "n:",n
            e=data_s[2][4:]
            print "e:",e
            c=data_s[3][4:]
            print "c:",c

            n=int(n,16)
            e=int(e,16)
            c=int(c,16)
            (p,q,d) = wiener_attack(n,e)
            print "p: ", p
            print "q: ", q
            print "d: ", d
            m=pow(c, d, n)
            #m=rsa_decrypt(n,c,e)
            print "m:",hex(m).replace("L","")
            time.sleep(1)
            s.send(hex(m).replace("L",""))
            print "send done"
        
    print "Connection closed."
    time.sleep(1)
    s.send("asdfwe")
    s.close()

netcat("39.107.33.90", 9999, '')

#res=raw_input("result needed:")
