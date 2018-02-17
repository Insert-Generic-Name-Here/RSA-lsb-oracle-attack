import socket, sys, json
import random, math, decimal

from tqdm import tqdm
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
pkg = (ServComn.recv_timeout(sct,timeout=0.05)).decode('utf-8')
pkg = json.loads(pkg)

e = pkg['e']
n = pkg['n']

print ("[RESPONSE] Server: ", pkg['ack'][0]) #[ACK] Public Key Exchanged
print ("[RESPONSE] Server: ", pkg['ack'][1]) #[ACK] Connection Established

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

for i in tqdm(range(k), desc='Decrypting'):
    lsb = ServComn.Oracle(sct, tmp)
    
    res = (LB+UB)/2
    if (lsb):
        LB = (LB+UB)/2  # we got an odd number 
    else:
        UB = (LB+UB)/2  # we got an even number 
    
    tmp = (tmp * ct_of_2) % n 
    
print('\nDecrypted.')
print('\nPossible PlainText: ', int(UB))
sct.close()
