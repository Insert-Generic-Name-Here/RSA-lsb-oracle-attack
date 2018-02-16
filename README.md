
# A Demonstration for the RSA LSB Oracle Attack

### Abstract
The main concern of this repository is the demonstration of retrieving a Plain RSA-Encrypted message knowing only the Least Significant Bit (LSB) of the plaintext. Finally to show the importance of padding the message before encryption we implement the RSA encryption algorithm with PKCS#1 v1.5 padding and we comment the effect of this attack on a message encrypted with the previous standard.

### File Tree 
*  /client.py (The Attacker): The Python Socket that Wants to Deduce an (Intercepted) Encrypted Message
*  /server.py (The Oracle): The Python Socket that Provides the Oracle Implementation
*  /lib/Cryptlib.py: The Python Module that Includes our RSA _(Plain/PKCS#1 v1.5)_ Implementation
*  /lib/PrimeGen.py: The Python Module that Includes our (Safe) Prime Number Generator.
*  /lib/ServerComn.py: The Python Module that Includes the functions crucial to the Communication between the Attacker and Oracle Sockets.

### The Attacker (Plain RSA Exploit)
The presented attack makes use of the Plain RSA Homomorphic Property to deduce the possible (encrypted) message through a series of tests.
Suppose we have an RSA encryption algorithm with public key (e, n) and private key (d, n).
The homomorphic property states that the product of two ciphertexts (modulo n) is equal _(if decrypted)_ to the product of the respected plaintexts (modulo n).

Applying the same principle to our problem, we multiply our _(intercepted)_ ciphertext, **c** with the ciphertext of **2**, that is **2^e (modulo n)** thus having: **c' = (2p)^e (modulo n)**, where **p** is the plaintext we're trying to deduce.

Sending **c'** to the Oracle we get the Least Significant Bit of **2p**. At this point we have two cases:

> if **p < n/2** then we have **2p < n** which is always an even number _(because n is an odd number as the product of two -large- prime numbers)_

> if **p > n/2** then we have **2p > n**  ->  **2p mod n = 2p - n**, which is always an odd number _(because n is an odd number as the product of two -large- prime numbers)_

So, if the Oracle responds with a **0** we know that **p** is less than **n/2** and if it responds with an **1** we know that **p** is greater (or equal) than **n/2**. 

Applying the above steps iteratively as many times as the bit length of n for 4p, 8p, ..., we get the location of p in respect to n/4, n/8, ..., until we finally get our _-secret-_ message p.

The algorithm that applies all the above is illustrated as such:
```python
LB = 0; UB = n
tmp = msg_ct * ct_of_2

for i in range(n.bit_length()):
    lsb = ServComn.Oracle(sct, tmp)
    res = (LB+UB)/2
    if (lsb):
        LB = (LB+UB)/2  # we got an odd number 
    else:
        UB = (LB+UB)/2  # we got an even number 
    tmp = (tmp * ct_of_2) % n 

deduced_ciphertext = int(UB)
```

This Algorithm is similar to Binary Search and it's Complexity is log2(N). And because N = 2^(2*rsa_bits) the Complexity of LSB Oracle Attack is 2*rsa_bits _(Linear in Respect to the Number of bits the RSA Algorithm uses for its encryption)_.

### The Oracle
A Black Box that decrypts any Plain RSA encrypted message and returns the Least Significant Bit (LSB) of the plaintext.

### Running the Attack
To Simulate the Oracle:
```python
python server.py <RSA-BITS>
```
To Simulate the Attacker:
```python
python client.py
```

### Attacking RSA/PKCS#1 v1.5 (and why it won't work...)
In our implementation of the RSA Algorithm (lib/Cryptlib.py) we added the PKCS#1 v1.5 padding:

> 0x0002 | Random-Non-Zero-Bytes | 0x00 | Message-Goes-Here

_Note: To encrypt a message with RSA/PKCS#1 v1.5 set the **padding** argument to **True**_

Trying to deduce a message encrypted with the above method using the Oracle LSB Attack will fail because the homomorphic property of the plain RSA is now lost due to the extra bytes that pad the message in order to reach the byte length of the modulus n.

This ensures the strength of this type of encryption against Oracle LSB Attack but the question is: is it safe against any other attack?
The answer is no. David BleichenBacher released a paper ([bleichenbacher98](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf)) that introduces a new attack on PKCS#1 v1.5 that retrieves the plaintext after a series of tests. This attack is called "Chosen Ciphertext" and it is based upon an oracle that returns if the padding of a ciphertext is correct or wrong.


