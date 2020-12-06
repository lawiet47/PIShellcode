import sys

f_in=open(sys.argv[1], "rb")
f_out=open(sys.argv[2], "wb")

xor_key = ['\x32', '\x47', '\x68', '\x84', '\x59', '\x91', '\x34' ,'\x17', '\x58', '\x13', '\x77', '\x69' ,'\x09' ,'\x11', '\x19', '\x94']

data_in=f_in.read()
data_out=[]
for i in range(0,len(data_in)):
	data_out.append(data_in[i] ^ ord(xor_key[i%len(xor_key)]))


f_out.write(bytearray(data_out))

f_out.close()
f_in.close()