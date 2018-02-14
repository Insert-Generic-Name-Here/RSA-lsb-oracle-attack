import socket, sys, json
import random, math, decimal

import lib.ServerComn as ServComn


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
c = random.randrange(n)
print ('[Target] PlainText: ', c)
msg_ct = pow(c, e, n)
print('[Target] CipherText: ', msg_ct)
ct_of_2 = pow(2, e, n)


# Beginning Attack
k = n.bit_length()
decimal.getcontext().prec = k
LB = decimal.Decimal(0)  # Lower Bound of the Plaintext
UB = decimal.Decimal(n)  # Upper Bound of the Plaintext


print ('Number of Tests: log2(N) = %d OR bit_len(N) = %d\n' %(math.ceil(math.log2(n)), k))
tmp = msg_ct * ct_of_2

for i in range(k):
    lsb = ServComn.Oracle(sct, tmp)
    
    res = (LB+UB)/2
    if (lsb):
        LB = (LB+UB)/2  # we got an odd number 
    else:
        UB = (LB+UB)/2  # we got an even number 
    
    tmp = (tmp * ct_of_2) % n 

    print('Decrypting... %d\r' %(int(UB)), flush=True)
    
print('\nDecrypted.')
print('\nPossible PlainText: ', int(UB))
sct.close()
