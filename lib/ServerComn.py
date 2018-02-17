import json, time


def BuildJson(word):
    json_msg = '{"msg": ['
    for vct in [word]:
        json_msg += "\""+repr(vct)+"\"" + ', '
    json_msg = json_msg[:-2] + ']}'
    return json_msg


def Oracle(the_socket, msg):
    pkg = {'ciphertext':msg}
    pkg = (json.dumps(pkg)).encode('utf-8')
    the_socket.sendall(pkg)

    pkg = recv_timeout(the_socket, timeout=0.05).decode('utf-8')
    pkg = json.loads(pkg)

    return pkg['lsb']


# Recieve full data with the recv socket function in Python
# http://www.binarytides.com/receive-full-data-with-the-recv-socket-function-in-python/
def recv_timeout(the_socket,timeout=2):
    #make socket non blocking
    the_socket.setblocking(0)
    #total data partwise in an array
    total_data=[]
    data=''
    #beginning time
    begin=time.time()
    while 1:
        #if you got some data, then break after timeout
        if total_data and time.time()-begin > timeout:
            break
        #if you got no data at all, wait a little longer, twice the timeout
        elif time.time()-begin > timeout*2:
            break
        #recv something
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(data)
                #change the beginning time for measurement
                begin = time.time()
            else:
                #sleep for sometime to indicate a gap
                time.sleep(0.1)
        except:
            pass
    #join all parts to make final string
    return b''.join(total_data)        


#Function for handling connections. This will be used to create threads
def ClienThread(conn, rsa):
    pkg = {'e':rsa.e, 'n': rsa.n,\
           'ack':['[ACK] Public Key Exchange.', '[ACK] Server Connection.']}
    pkg = (json.dumps(pkg)).encode('utf-8')
    conn.sendall(pkg)

    while(True):
        try:
            pkg = (recv_timeout(conn, timeout=0.05)).decode('utf-8') # Recieve the Encrypted Message
            pkg = json.loads(pkg)
            cipherText = pkg['ciphertext']
            # print('Cipher Text: ', cipherText)
            plainText = rsa.Decrypt(cipherText)
            print('Decrypted Message: ', plainText)
            pkg = {'lsb': int(plainText % 2)}
            pkg = (json.dumps(pkg)).encode('utf-8')
            conn.sendall(pkg)
        except json.decoder.JSONDecodeError:
            print ('Connection Terminated.\n')
            conn.close()
            break