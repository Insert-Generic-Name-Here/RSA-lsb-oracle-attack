import lib.PrimeGen as pg
import gmpy2


class RSA:
    def __init__(self, bits, sp=False):
        pgen = pg.PrimeGen()
        if (sp == False):
            p = pgen.Generate(bits) # Generate a *safe prime* with __bits__ BITS.
            print ('[ACK] Computed Random Prime p.')
            q = pgen.Generate(bits) # Generate a *safe prime* with __bits__ BITS.
            print ('[ACK] Computed Random Prime q.')
            phi = (p-1)*(q-1)       # euler's phi function for n
        else:
            p = pgen.GenerateSafe(bits) # Generate a *safe prime* with __bits__ BITS.
            print ('[ACK] Computed Random Prime p.')
            q = pgen.GenerateSafe(bits) # Generate a *safe prime* with __bits__ BITS.
            print ('[ACK] Computed Random Prime q.')
            phi = (p-1)*(q-1)       # euler's phi function for n
        
        self.n = p * q
        self.e = 2**16 + 1
        self.__d = gmpy2.invert(self.e, phi)
        print ('[ACK] RSA-%d Initiated Successfully.' %(bits))
        
    def __PublicKey(self):
        return self.e, self.n
    
    def __PrivateKey(self):
        return self.__d, self.n
    
    def Encrypt(self, plainText):
        [e, n] = self.__PublicKey()
        return pow(plainText, e, n)
    
    def Decrypt(self, cipherText):
        [d, n] = self.__PrivateKey()
        return pow(cipherText, d, n)