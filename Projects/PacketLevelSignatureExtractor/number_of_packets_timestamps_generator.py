from itertools import count
from scapy.all import *
packetsAll = rdpcap('sengled-bulb-onoff.wlan1.local.pcap')
'''packetsAll = rdpcap('roomba-vacuum-robot.wlan1.local.pcap')'''

device_ip='192.168.1.246'
packets=[]
syn_packets=0
synack_packets=0
ack_packets=0

for index in range(len(packetsAll)):
    p=packetsAll[index]
    if 'IP' in p and (p['IP'].src == device_ip or p['IP'].dst == device_ip) :
        packets.append(p)

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

counter=0

for index in range(len(packets)):
    if(index==len(packets) or (index==len(packets)-1) or index==len(packets)-2):
        break
    packet1=packets[index]
    packet2=packets[index+1]
    packet3=packets[index+2]
    if 'IP' in packet1 and (packet1['IP'].src == device_ip or packet1['IP'].dst == device_ip) :
        if 'TCP' in packet1 and 'TCP' in packet2 and 'TCP' in packet3:
            f1=packet1['TCP'].flags
            f2=packet2['TCP'].flags
            f3=packet3['TCP'].flags
            if (f1 & ACK) or (f1 & FIN) or (f1 & RST) or (f1 & PSH) or (f1 & URG) or (f1 & ECE) or (f1 & CWR):
                continue
            if (f2 & FIN) or (f2 & RST) or (f2 & PSH) or (f2 & URG) or (f2 & ECE) or (f2 & CWR):
                continue
            if (f2 & SYN) and ((f2 & ACK)==0):
                continue 

            # if (f3 & SYN) or (f3 & FIN) or (f3 & RST) or (f3 & PSH) or (f3 & URG) or (f3 & ECE) or (f3 & CWR):
            #     continue
            if (f1 & SYN) and (f2 & SYN) and (f2 & ACK):
                #print(packet1.time)
                counter+=1

first_packet_time=0
packet_in_interval=0
sum_packet_in_interval=0
counter_for_packet_in_interval=0

for index in range(len(packetsAll)):
    packet1=packetsAll[index]
    if(first_packet_time==0):
        first_packet_time=packet1.time
        print("---------------------------------------")
        print("First Packet time: ",first_packet_time)
        packet_in_interval=1
    else:
        if(packet1.time-first_packet_time>=15):
            print("Last Packet time: ",packet1.time)
            print("Packets in 15 sec interval: ", packet_in_interval)
            print("---------------------------------------")
            sum_packet_in_interval+=packet_in_interval
            counter_for_packet_in_interval+=1
            first_packet_time=0
        else:
            packet_in_interval+=1

for index in range(len(packets)):
    packet1=packets[index]

    if 'IP' in packet1 and (packet1['IP'].src == device_ip or packet1['IP'].dst == device_ip) :
        if 'TCP' in packet1:
            f1=packet1['TCP'].flags
            if (f1 & ACK) or (f1 & FIN) or (f1 & RST) or (f1 & PSH) or (f1 & URG) or (f1 & ECE) or (f1 & CWR):
                continue 
            syn_packets+=1

for index in range(len(packets)):
    packet2=packets[index]

    if 'IP' in packet2 and (packet2['IP'].src == device_ip or packet2['IP'].dst == device_ip) :
        if 'TCP' in packet2:
            f2=packet2['TCP'].flags
            if (f2 & FIN) or (f2 & RST) or (f2 & PSH) or (f2 & URG) or (f2 & ECE) or (f2 & CWR):
                continue
            if (f2 & SYN) and ((f2 & ACK)==0):
                continue 
            if ((f2 & SYN) and (f2 & ACK)):
                synack_packets+=1

print("Total number of packets: ", len(packetsAll))
#print("Total number of packets for device", len(packets))
print("Average packet in 15 sec interval: ", sum_packet_in_interval/counter_for_packet_in_interval)
print("Total time stamps: "+str(counter))
print("Number of SYN packets: ", syn_packets)
print("Number of SYN-ACK packets: ", synack_packets)
print("Average number of Packets per connection, n: ", len(packetsAll)/(syn_packets))
print("Number of packets to be considered: ", (sum_packet_in_interval/counter_for_packet_in_interval)+(len(packetsAll)/(syn_packets)))

'''
index=0

for i in range(len(packets)):
    if(index==len(packets) or (index==len(packets)-1) or index==len(packets)-2):
        break
    packet1=packets[index]
    if 'TCP' in packet1:
        f1=packet1['TCP'].flags    
        if ((f1 & SYN)==0):
            index+=1
            continue
        for index2 in range(index+1,len(packets)):
            packet2=packets[index2]
            if 'TCP' in packet2:
                f2=packet2['TCP'].flags 
                if ((f2 & SYN)==0) and ((f2 & ACK)==0):
                    continue
                if (f2 & SYN) and ((f2 & ACK)==0):
                    index=index2
                    break
                if (f2 & SYN) and (f2 & ACK):
                    if packet1['TCP'].sport != packet2['TCP'].dport:
                        continue
                    for index3 in range(index2+1,len(packets)):
                        packet3=packets[index3]
                        if 'TCP' in packet3:
                            f3=packet3['TCP'].flags 
                            if ((f3 & SYN)==0) and ((f3 & ACK)==0):
                                continue
                            if (f3 & SYN) and ((f3 & ACK)==0):
                                continue
                            if ((f3 & SYN)==0) and (f3 & ACK):
                                if packet1['TCP'].sport != packet3['TCP'].sport:
                                    continue
                                print(packet1.time)
                                counter+=1
                                index=index3
                                break 
                    break
'''