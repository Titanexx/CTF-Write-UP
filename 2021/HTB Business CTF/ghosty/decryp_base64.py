from base64 import b64decode as b64d
from binascii import hexlify as hex, unhexlify as unhex

service_xor_key = unhex(b"2c3e19155e723d23130029681e17074e200435484f5f7c24223556166f18342817185f4c")
service_key = b"mmgb4UNqb3JWGZm7n7Gt9kTtBm6w9pbVWuah"

key = ''.join([chr(service_key[i] ^ service_xor_key[i]) for i in range(len(service_key))]).encode('latin1')
print(hex(key))

def decode(input):
	res = ""
	for i in range(len(input)):
		res += chr(input[i] ^ key[i%len(key)])
	print(res)
	return res

decode(b64d("HSoRAhh4Fz0SRg5aNzkZ"))
decode(b64d("CRg7LjVkJgAjdi1rBhg5PBw="))
decode(b64d("HQARER5QEiAUby5WOj8FCiFVBmAhXUY0Dy8TPRUdJAwlA0pyJCENHgVJLwUYXQdQLj4/CSpSBlk="))
decode(b64d("FCMaFh5CODcI"))
decode(b64d("Ij4aWQ9fFg=="))
decode(b64d("bjBeARlUEjYcWg0RPDUPWQpWHlkCUQgDCDkEDiEbdlEhAVIEbiILHg9T"))
decode(b64d("bzQWGBlT"))

# $ python solve.cryptor.py
# b'41537e776a2773527133633f594d6a794e33723c76342850605860615668567e406d3e24'
# \your_documents
# HKEY_CURRENT_USER
# \Software\Microsoft\Windows\CurrentVersion\WindowsUpdate
# UpdateKey
# cmd.exe
# /c vssadmin.exe Delete Shadows /all /quiet
# .ghost
