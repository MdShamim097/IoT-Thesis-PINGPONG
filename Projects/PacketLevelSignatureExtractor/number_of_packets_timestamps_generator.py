from itertools import count
from scapy.all import *
import math

packetsAll = rdpcap('tplink-plug.wlan1.local.pcap')

device_ip='192.168.1.246'

packets=[]

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

timestamps_counter=0

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
                timestamps_counter+=1

first_packet_time=0
packet_in_interval=0
sum_packet_in_interval=0
counter_for_packet_in_interval=0
max_packet_in_interval=0
threshold_for_packet_in_interval=50
inclusion_window_size=15

for index in range(len(packets)):
    packet1=packets[index]
    if(first_packet_time==0):
        first_packet_time=packet1.time
        packet_in_interval=1
    else:
        if(packet1.time-first_packet_time>=inclusion_window_size):
            first_packet_time=0
            if packet_in_interval>=threshold_for_packet_in_interval:
                sum_packet_in_interval+=packet_in_interval
                counter_for_packet_in_interval+=1
                if packet_in_interval > max_packet_in_interval:
                    max_packet_in_interval=packet_in_interval
        else:
            packet_in_interval+=1

syn_packets=0
synack_packets=0

for index in range(len(packets)):
    packet1=packets[index]
    if 'TCP' in packet1:
        f1=packet1['TCP'].flags
        if (f1 & ACK) or (f1 & FIN) or (f1 & RST) or (f1 & PSH) or (f1 & URG) or (f1 & ECE) or (f1 & CWR):
            continue 
        syn_packets+=1

for index in range(len(packets)):
    packet2=packets[index]
    if 'TCP' in packet2:
        f2=packet2['TCP'].flags
        if (f2 & FIN) or (f2 & RST) or (f2 & PSH) or (f2 & URG) or (f2 & ECE) or (f2 & CWR):
            continue
        if (f2 & SYN) and ((f2 & ACK)==0):
            continue 
        if ((f2 & SYN) and (f2 & ACK)):
            synack_packets+=1


avg_packet_per_interval=sum_packet_in_interval/counter_for_packet_in_interval

print("Total number of packets for device: ", len(packets))
print("Average packet in 15 sec interval: ", avg_packet_per_interval)
print("Maximum packet in 15 sec interval: ",max_packet_in_interval)
print("Total time stamps: ",timestamps_counter)
print("Number of SYN packets: ", syn_packets)
print("Number of SYN-ACK packets: ", synack_packets)

triggered_event_count=100

if timestamps_counter!=0:
    avg_packet_per_connection_one=len(packets)/(timestamps_counter)
    n=avg_packet_per_interval + avg_packet_per_connection_one
    total_packets_considered=n*triggered_event_count
    if total_packets_considered>len(packets):
        n=max(avg_packet_per_interval, avg_packet_per_connection_one)
        total_packets_considered=n*triggered_event_count
        if total_packets_considered>len(packets):
            n=(avg_packet_per_interval + avg_packet_per_connection_one)/2
            total_packets_considered=n*triggered_event_count
            if total_packets_considered>len(packets):
                n=min(avg_packet_per_interval, avg_packet_per_connection_one)
                total_packets_considered=n*triggered_event_count
                if total_packets_considered>len(packets):
                   n=len(packets)/triggered_event_count 
    
    n=math.floor(n)
    print("Average number of Packets per connection(considering simultaneous connections as one) : ", avg_packet_per_connection_one)
    print("Number of packets to be considered: ", n)
    
else:
    avg_packet_per_connection_synack=len(packets)/(synack_packets)
    n=avg_packet_per_interval + avg_packet_per_connection_synack
    total_packets_considered=n*triggered_event_count
    if total_packets_considered>len(packets):
        n=max(avg_packet_per_interval, avg_packet_per_connection_synack)
        total_packets_considered=n*triggered_event_count
        if total_packets_considered>len(packets):
            n=(avg_packet_per_interval + avg_packet_per_connection_synack)/2
            total_packets_considered=n*triggered_event_count
            if total_packets_considered>len(packets):
                n=min(avg_packet_per_interval, avg_packet_per_connection_synack)
                total_packets_considered=n*triggered_event_count
                if total_packets_considered>len(packets):
                   n=len(packets)/triggered_event_count 
                   h=1
    
    n=math.floor(n)
    print("Average number of Packets per connection : ", avg_packet_per_connection_synack)
    print("Number of packets to be considered: ", n)
