import socket
import threading
import sys

import lib.Cryptlib2 as Cryptlib2
import lib.ServerComn as ServComn

#---------------------------------------------------------------------------------
#---------------------------SOCKET CREATION; SOCKET BIND--------------------------
#---------------------------------------------------------------------------------    
HOST = "localhost"   # Symbolic name meaning all available interfaces
PORT = 5000 # Arbitrary non-privileged port  
    
sct = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sct.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
print ('[ACK] Socket created')
    
try:
    sct.bind((HOST, PORT))
except socket.gaierror as err:
    print ('[ERR] Socket:', err)
    sys.exit()
print ('[ACK] Socket bind complete')
 
rsa = Cryptlib2.RSA(int(sys.argv[1]))

print ('RSA Public Key\ne: %d\nn: %d' %(rsa.e, rsa.n))
    
sct.listen(10)
print ('[ACK] Socket now listening')
#---------------------------------------------------------------------------------

#---------------------------------------------------------------------------------
#------------------------LISTENING TO INCOMING CONNECTIONS------------------------
#--------------------------------------------------------------------------------- 
while 1:
    try:
        #wait to accept a connection - blocking call
        conn, addr = sct.accept()
        print ('Connected with ' + addr[0] + ':' + str(addr[1]))
        threading.Thread(target=ServComn.ClienThread, args=(conn, rsa),).start()
    except KeyboardInterrupt:
        print ('\nServer Forced Shutdown...')
        break
sct.close()
#--------------------------------------------------------------------------------- 
