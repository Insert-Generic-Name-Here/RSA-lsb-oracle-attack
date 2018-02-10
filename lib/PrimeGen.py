import random

class PrimeGen:
    def __init__(self):
        self.p = None
    
    # Make 20 Ramdom Tests to determine if the number p is a prime
    # According to the below reverse-opposite theorem:
    '''
        If there is a number *a* __not equal__ to *zero* and a 
        __prime__ *p* that is __not divided__ by *a* so that:
        
                a^(p-1) mod p =/= 1 <=> a^p mod p =/= a
        
        Then the number *p* __is not__ prime.
    '''
    def __IsPrime(self, p, tests):
        cnt = 1
        while cnt < tests:
            a = random.randrange(1, p)
            if pow(a, p, p) == a:
                cnt += 1
            else:
                break
        if cnt == tests:
            return True
        else:
            return False       
    
    # Auxiliary Method for Generating a Prime Number
    def Generate(self, B, tests=20):
        FND = False
        while FND == False:
            lb = 2**(B - 1)
            p = random.randrange(lb, 2 * lb)
            FND = self.__IsPrime(p, tests)
        return p
    
    # The Method that Generates a *safe* Prime Number
    def GenerateSafe(self, B, tests=20):
        p = self.Generate(B - 1, tests)
        q = 2 * p + 1
        while not self.__IsPrime(q, tests):
            p = self.Generate(B - 1, tests)
            q = 2 * p + 1
        return q