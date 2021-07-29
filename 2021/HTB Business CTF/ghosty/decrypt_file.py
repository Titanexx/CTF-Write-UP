from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
from base64 import b64decode as b64d
from binascii import hexlify as hex, unhexlify as unhex
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

service_xor_key = unhex(b"2c3e19155e723d23130029681e17074e200435484f5f7c24223556166f18342817185f4c")
service_key = b"mmgb4UNqb3JWGZm7n7Gt9kTtBm6w9pbVWuah"

key = ''.join([chr(service_key[i] ^ service_xor_key[i]) for i in range(len(service_key))]).encode('latin1')

def decode(input):
    res = ""
    for i in range(len(input)):
        res += chr(input[i] ^ key[i%len(key)])
    return res

password = b'd31dd518-8614-4162-beae-7a5a2ad86cc6'
password = decode(password).encode('latin1')

with open("Confidential.pdf.ghost","rb") as f:
    enc_data = f.read() 

salt = enc_data[:32]
enc_data = enc_data[32:]

keys = PBKDF2(password, salt, dkLen=48, count=50000)
key = keys[:32]
iv = keys[32:]

print("Key:",hex(key))
print("IV:",hex(iv))

cipher = AES.new(key, AES.MODE_CFB, iv=iv,segment_size=128)
dec_data = cipher.decrypt(enc_data)

with open("Confidential.pdf","wb") as f:
    f.write(dec_data)

