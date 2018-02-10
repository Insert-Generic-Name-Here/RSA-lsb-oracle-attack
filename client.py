import socket
import random
import threading as thread
import json
import math
import sys

import lib.ServerComn as ServComn

def RsaOracleLsbAttack(msg):
    sct.sendall(ServComn.BuildJson(msg).encode('utf-8')+'|'.encode('utf-8'))
    recv_msg = sct.recv(4096).decode('utf-8')
    msg_lsb = int(recv_msg.split('|')[0])
    return msg_lsb

#---------------------------------------------------------------------------------
#-----------------------------CONNECT TO SERVER SOCKET----------------------------
#---------------------------------------------------------------------------------
HOST = "localhost"		# Symbolic name meaning all available interfaces
PORT = 5000 			# Arbitrary non-privileged port

sct = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
	sct.connect((HOST,PORT))
except Exception as e:
	print (e)
	sys.exit(1)
#---------------------------------------------------------------------------------

#---------------------------------------------------------------------------------
#-------------------------------MAIN SOCKET CODE----------------------------------
#---------------------------------------------------------------------------------
msg_rcv = sct.recv(4096)
msg_rcv = msg_rcv.decode('utf-8').split('|')

e = int(json.loads(msg_rcv[0])['msg'][0])
n = int(json.loads(msg_rcv[1])['msg'][0])

print ("[RESPONSE] Server: ", msg_rcv[2]) #[ACK] Public Key Exchanged
print ("[RESPONSE] Server: ", msg_rcv[3]) #[ACK] Connection Established

# Suppose we Intercepted the Below Message
# c = random.randrange(n)
# c = 93278
# c = 11111112222224  # 14 digits
# c = 111111122222249 # 15 digits
c = 12341234123412341234 # 20 digits


print ('[Target] PlainText: ', c)
msg_ct = pow(c, e, n)
print('[Target] CipherText: ', msg_ct)

# Beginning Attack
LB = 0 # Lower Bound of the Plaintext
UB = n # Upper Bound of the Plaintext

cnt = 0
msg_atk = pow(2, e, n)
print ('PK -> n: %d' %(n))
print ('Estimated Number of Tests: %d' %(math.ceil(math.log2(n))))
# print(msg_atk)
# Let's Send it to the Oracle to see What it Will Tell us

while True:        
    if (UB - LB <= 1):
        break

    cnt = cnt + 1
    print('Round: %d' %(cnt))

    msg_ct = msg_ct*msg_atk
    lsb = RsaOracleLsbAttack(msg_ct)
    if ( lsb == 1 ): # we got an odd number
        LB = (LB+UB)/2
    elif ( lsb == 0 ): # we got even number
        UB = (LB+UB)/2

    print('Lower Bound: %.10f' %(LB))
    print('Upper Bound: %.10f' %(UB))

print ('After %d tests, we now know that the unknown message is: %d' %(cnt, int(UB)))
print ('\n')

sct.close()
