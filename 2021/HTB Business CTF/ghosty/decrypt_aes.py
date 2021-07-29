from binascii import hexlify, unhexlify
import os
import subprocess

with open("pcap.txt","rb") as f:
  data=f.read()

data = unhexlify(data)
packets = []
cur_index = 0

while cur_index < len(data):
  len_packet = int.from_bytes(data[cur_index:cur_index+4],'little')
  cur_index += 4
  packets.append(hexlify(data[cur_index:cur_index+len_packet]))
  cur_index += len_packet

for p in packets:
  res = subprocess.run(["go","run","decrypt_aes.go","-key","3132333435363132333435363132333435363132333435363132333435363132","-ciphertext",p.decode('latin1')],stdout=subprocess.PIPE)
  print('----------------------')
  # print(p.decode('latin1'))
  if(b'This program cannot be run in DOS mode' in res.stdout):
    with open("cryptor.exe","wb") as f:
      f.write(res.stdout)
      print("[Exe saved in cryptor.exe]")
  else:
    print(res.stdout.decode('latin1').strip())