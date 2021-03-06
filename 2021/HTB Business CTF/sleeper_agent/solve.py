def decrypt(arr):
	res = ''
	for i in range(len(arr)):
		res += chr(arr[i][0] ^ i + 0x14)

	return res

def prepare_secret(arr):
	arr = [arr[i:i+2] for i in range(0,len(arr),2)]
	arr.sort(key=lambda e: e[1])
	return arr

chall = {
	'secret5': b'\x76\x03\x7c\x05\x61\x01\x7b\x04\x64\x02\x64\x00',
	'secret0': b'\x62\x02\x64\x03\x64\x00\x60\x01',
	'secret3': b'\x64\x03\x7d\x04\x79\x02\x77\x00\x79\x01',
	'secret2': b'\x65\x02\x63\x03\x6c\x01\x67\x00\x74\x05\x7d\x04',
	'secret4': b'\x75\x2b\x61\x1f\x57\x0c\x3d\x45\x04\x51\x12\x46\x0c\x4d\x69\x44\x78\x21\x2e\x40\x63\x3f\x16\x33\x2c\x42\x48\x1e\x20\x2d\x75\x32\x48\x5c\x0e\x23\x38\x04\x15\x43\x55\x1d\x60\x3e\x45\x0d\x78\x36\x7c\x26\x4a\x18\x09\x3d\x29\x39\x3c\x4b\x74\x0b\x30\x4a\x14\x52\x7c\x38\x01\x3b\x5c\x06\x5f\x08\x76\x01\x71\x00\x0f\x4f\x6a\x1a\x5a\x59\x09\x3a\x4a\x05\x09\x57\x46\x20\x76\x2a\x11\x35\x6b\x47\x06\x37\x75\x0e\x56\x1c\x56\x5a\x21\x49\x46\x54\x3f\x3c\x33\x2c\x57\x10\x4d\x15\x14\x12\x5a\x25\x7e\x02\x40\x16\x3f\x34\x61\x48\x49\x07\x1d\x31\x02\x53\x3d\x30\x0d\x2f\x0d\x41\x46\x28\x03\x4e\x7d\x11\x4c\x58\x40\x13\x6d\x1b\x40\x4c\x5b\x0f\x78\x09\x2f\x0a\x1e\x56\x13\x50\x58\x5b\x09\x24\x78\x03\x18\x14\x16\x2e\x73\x29\x49\x19\x07\x22\x01\x55\x03\x27\x65\x17',
}

for k,v in chall.items():
	print(k,repr(decrypt(prepare_secret(v))))