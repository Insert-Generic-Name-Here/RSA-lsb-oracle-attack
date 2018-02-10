import json
import time


def BuildJson(word):
    json_msg = '{"msg": ['
    for vct in [word]:
        json_msg += "\""+repr(vct)+"\"" + ', '
    json_msg = json_msg[:-2] + ']}'
    return json_msg


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
    msg_snd = ((BuildJson(rsa.e) + '|').encode('utf-8')            +
              ((BuildJson(rsa.n)+'|')).encode('utf-8')             +
              (('[ACK] Public Key Exchange.'+'|').encode('utf-8')) +
              (('[ACK] Server Connection.'+'|').encode('utf-8')))
    
    conn.sendall(msg_snd)

    while(True):
        recv_msg = recv_timeout(conn, timeout=0.1)
        recv_msg = recv_msg.decode('utf-8') # Recieve the Encrypted Message
        recv_msg = recv_msg.split('|')
        cipherText = int(json.loads(recv_msg[0])['msg'][0])
        # print('Cipher Text: ', cipherText)
        plainText = rsa.Decrypt(cipherText)
        print('Plain Text: ', plainText)

        conn.sendall(str(plainText%2).encode('utf-8')+'|'.encode('utf-8'))