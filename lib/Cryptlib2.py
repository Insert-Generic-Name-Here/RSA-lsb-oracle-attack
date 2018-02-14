import lib.PrimeGen as pg
import math, gmpy2, random


class RSA:
    def __init__(self, bits):
        pgen = pg.PrimeGen()
        p = pgen.Generate(bits) # Generate a *safe prime* with __bits__ BITS.
        print ('Computed Random Prime p.')
        q = pgen.Generate(bits) # Generate a *safe prime* with __bits__ BITS.
        print ('Computed Random Prime q.')
        phi = (p-1)*(q-1)       # euler's phi function for n
        
        self.n = p * q
        self.e = 2**16 + 1
        self.__d = gmpy2.invert(self.e, phi)
        print ('RSA-%d Initiated Successfully.' %(bits))
        
    def __GenerateByteSequence(self, byte_length):
        byteSeq = bytearray(byte_length)
        for byte in range(byte_length):
            byteSeq[byte] = random.randint(1, 15)
        return byteSeq
        
    def __PadMessage(self, plainText, n):
        EB = math.ceil(n.bit_length()/8) # byte-size of Encryption Block (EB)
        DB = math.ceil(plainText.bit_length()/8)       # byte-size of Data Block (DB)
        PS = EB - 3 - DB                        # byte-size of Padding String (PS)
        if not(DB <= EB - 11):
            raise ValueError('Byte Size: Message > Encryption Block - 11.')
        else:
            paddingString = self.__GenerateByteSequence(PS)
        plainTextHex = plainText.to_bytes((plainText.bit_length() + 7)//8, byteorder='big')
        paddedText = bytes.fromhex('0002') + paddingString + bytes.fromhex('00') + plainTextHex
        return paddedText
        
    def __PublicKey(self):
        return self.e, self.n
    
    def __PrivateKey(self):
        return self.__d, self.n
    
    def Encrypt(self, plainText, padding=False):
        [e, n] = self.__PublicKey()
        if padding:
            plainTextPadded = self.__PadMessage(plainText, n)
            tmp = int.from_bytes(plainTextPadded, byteorder='big')
            cipherText = pow(tmp, e, n)
        else:
            cipherText = pow(plainText, e, n)
        return cipherText
    
    def Decrypt(self, cipherText, padding=False):
        [d, n] = self.__PrivateKey()
        decipherText = pow(cipherText, d, n)
        if padding:
            decipherTextHex = int(decipherText).to_bytes((n.bit_length() + 7)//8, byteorder='big')
            if (decipherTextHex[0:2] == b'\x00\x02'):
                decipherText = int.from_bytes(decipherTextHex.split(bytearray(1))[-1], byteorder='big')
            else: 
                raise ValueError('PKCS Encryption: Wrong Padding.')
        return decipherText