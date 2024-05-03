import hashlib
import os
import itertools
import io
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import itertools
import io
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

##########################BEGIN Part 1 : Bruteforce Private DSA key###########################

key_with_error = '''-----BEGIN DSA PRIVATE KEY-----
MIIBuQIBAAKBgQC973oUk7##7lilY1gwPAtXvTNDWbPbQhlstbax0b6LMyPCE1xf
gwLoercCPm1OWl65pRExUR5g0CJxFZNekWQKh7fNqzMQt5fUKMMwtU4Im05M+sTb
FeVYTiUrEdWjAbF5XvN6RgcEp7rL1ZX4VucElbxoAIvek+Aqfr0Zg/ltBQIVAKoK
+9q7j+T3esxgCTQMI2BQKSQnAn8dphjfU5jwzf+Nst9rkn1tZO0afBuzvNMRS8BF
9LCJ2q2Nly9Orifz8IJqkhIGnEy802QyjUgLJAgYlBWarK1vJTQApgwN3t66mE9J
Oc3gBgi9skZ/AQimaMb8YiHskbhn85ISpgJcvkjnL2KiTA/FtwTbzAj/Z5Sqv0xK
ax2GAoGBAJpAieRPdSlKrM7x5gVlPZiI5vXEdw83IBIsK0W5XTtD5LeDfemLQDO9
Qz49svcBuH6pdINnvQ3CrxaiJyJTMnfNNK9NuBeW2Q4KZJxQflXhcNuXcG0i2m0l
QizOAkzQKKHeIMk5+7KoD3tgm4xzJvPewhaSca6upI3xVUobnjs/AhR7SchExgXv
cJMj8CVGbPRdKkKBUg==
-----END DSA PRIVATE KEY-----
'''

def verify(key):
    try:
        possible_key = DSA.import_key(io.StringIO(key).getvalue())
        print("The key is correct:")
        print(key)
        return True
    except ValueError:
        return False

def bruteforce(key_with_error):
    key_list = list(key_with_error) #Convert the string to a list
    possible_characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' #Characters to try
    #Generate all possible iterations for the given characterset for 2 characters
    iterations = itertools.product(possible_characters, repeat=2)
    for char1, char2 in iterations:
        #Modify the positions in the key (given as input) with the characters in this iteration
        key_list[54] = char1
        key_list[55] = char2
        #Validate the key by using the verify() function
        modified_key = ''.join(key_list) #Convert the list back to a string
        if verify(modified_key):
            return modified_key
    return None #Return None if no valid private key is found

########## MAIN FOR TESTING ################
#def main():
# c = bruteforce(key_with_error)
# print(c)
#if __name__ == "__main__":
# main()

########## END MAIN FOR TESTING ################

##########################BEGIN PART 2 #####################

plain1 = b'\xd1\x31\xdd\x02\xc5\xe6\xee\xc4\x69\x3d\x9a\x06\x98\xaf\xf9\x5c\x2f\xca\xb5\x87\x12\x46\x7e\xab\x40\x04\x58\x3e\xb8\xfb\x7f\x89\x55\xad\x34\x06\x09\xf4\xb3\x02\x83\xe4\x88\x83\x25\x71\x41\x5a\x08\x51\x25\xe8\xf7\xcd\xc9\x9f\xd9\x1d\xbd\xf2\x80\x37\x3c\x5b\xd8\x82\x3e\x31\x56\x34\x8f\x5b\xae\x6d\xac\xd4\x36\xc9\x19\xc6\xdd\x53\xe2\xb4\x87\xda\x03\xfd\x02\x39\x63\x06\xd2\x48\xcd\xa0\xe9\x9f\x33\x42\x0f\x57\x7e\xe8\xce\x54\xb6\x70\x80\xa8\x0d\x1e\xc6\x98\x21\xbc\xb6\xa8\x83\x93\x96\xf9\x65\x2b\x6f\xf7\x2a\x70'

#Incorrect input block
plain2 = b'\xd1\x31\xdd\x02\xc5\xe6\xee\xc4\x69\x3d\x9a\x06\x98\xaf\xf9\x5c\x2f\xca\xb5\x00\x12\x46\x7e\xab\x40\x04\x58\x3e\xb8\xfb\x7f\x89\x55\xad\x34\x06\x09\xf4\xb3\x02\x83\xe4\x88\x83\x25\x00\x41\x5a\x08\x51\x25\xe8\xf7\xcd\xc9\x9f\xd9\x1d\xbd\x72\x80\x37\x3c\x5b\xd8\x82\x3e\x31\x56\x34\x8f\x5b\xae\x6d\xac\xd4\x36\xc9\x19\xc6\xdd\x53\xe2\x34\x87\xda\x03\xfd\x02\x39\x63\x06\xd2\x48\xcd\xa0\xe9\x9f\x33\x42\x0f\x57\x7e\xe8\xce\x54\xb6\x70\x80\x28\x0d\x1e\xc6\x98\x21\xbc\xb6\xa8\x83\x93\x96\xf9\x65\xab\x6f\xf7\x2a\x70'

def verify_hash(temp):
    return (hashlib.md5(plain1).digest() == hashlib.md5(temp).digest() and plain1 != temp)

def hash_collision(plain2):
    possible_hash = plain2
    for brute_force_bytes in itertools.product(range(256), repeat=3):
        temp_plain2 = bytearray(plain2)
        temp_plain2[19] = brute_force_bytes[0]
        temp_plain2[45] = brute_force_bytes[1]
        temp_plain2[59] = brute_force_bytes[2]
        if verify_hash(temp_plain2):
            return bytes(temp_plain2)

print(hash_collision(plain2))

##########################END PART 2 #####################
