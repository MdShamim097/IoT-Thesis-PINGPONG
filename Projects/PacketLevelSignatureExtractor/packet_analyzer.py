from struct import pack
from scapy.all import *
import sys
def time_to_timestamp(tt,timezone):
	tt=tt+timezone*3600
	tt=int(tt)
	sec_day=24*60*60
	days_in_year=365
	year = [days_in_year,days_in_year,days_in_year+1,days_in_year]
	months = [31,28,31,30,31,30,31,31,30,31,30,31]
	for i in range(3):
		year[i+1]=year[i+1]+year[i]
	yy = int(tt/(year[3]*sec_day))
	tt=tt-(year[3]*sec_day*yy)
	yy=1970+yy*4
	mon=0;
	for i in range(4):
		if tt>=year[3-i]*sec_day:
			tt=tt%(year[3-i]*sec_day)
			yy=yy+4-i
			break
	if yy%4==0:
		months[1]=months[1]+1
	for i in range(11):
		months[i+1]=months[i+1]+months[i]
	for i in range(12):
		if tt>=months[11-i]*sec_day:
			tt=tt-months[11-i]*sec_day
			mon=12-i
			break
	mon=mon+1
	if mon>12:
		mon=mon-12
	dd=int(tt/sec_day)
	dd=dd+1
	tt=tt%sec_day
	hh=int(tt/(60*60))
	tt=tt%(60*60)
	mm=int(tt/(60))
	tt=tt%(60)
	return [yy,mon,dd,hh,mm,tt]

def str_timestamp(tt,timezone):
	arr=time_to_timestamp(tt,timezone)
	mer="AM"
	if arr[3]==0:
		arr[3]=12
	elif arr[3]==12:
		mer="PM"
	elif arr[3]>12:
		arr[3]=arr[3]-12
		mer="PM"
	yy=str(arr[0])
	mon=str(arr[1])
	dd=str(arr[2])
	hh=str(arr[3])
	mm=str(arr[4])
	ss=str(arr[5])
	ans=mon.zfill(2)+"/"+dd.zfill(2)+"/"+yy+" "+hh.zfill(2)+":"+mm.zfill(2)+":"+ss.zfill(2)+" "+mer;
	return ans

	

def get_timestamp(input_file,output_timestamp,device_ip,duration,gap):
	packets = rdpcap(input_file)
	dict = {}
	out = open(output_timestamp,"w")
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20
	ECE = 0x40
	CWR = 0x80
	new_dict={}
	var=''
	for packet in packets:
		if 'IP' in packet and (packet['IP'].src == device_ip or packet['IP'].dst == device_ip) :
			key=''
			foreign_ip=''
			found=False
			length=0
			if packet['IP'].src == device_ip:
				if 'TCP' in packet and len(packet['TCP'])>0 :
					f=packet['TCP'].flags
					if (f & FIN ) or (f & RST):
						continue
					else:
						key = 'TCP:'+packet['IP'].dst+' '+str(packet['TCP'].sport)+' '+str(packet['TCP'].dport)
						foreign_ip=packet['IP'].dst
						length=len(packet['TCP'])
						found=True
				elif 'UDP' in packet and len(packet['UDP'])>0 :
					if packet['UDP'].sport != 53 and packet['UDP'].dport!=53 :
						key = 'UDP:'+packet['IP'].dst+' '+str(packet['UDP'].sport)+' '+str(packet['UDP'].dport)
						foreign_ip=packet['IP'].dst
						found=True
						length=len(packet['UDP'])
					else:
						continue
			else:
				if 'TCP' in packet and len(packet['TCP'])>0:
					f=packet['TCP'].flags
					if (f & FIN) or (f & RST):
						continue
					else:
						key = 'TCP:'+packet['IP'].src+' '+str(packet['TCP'].dport)+' '+str(packet['TCP'].sport)
						foreign_ip=packet['IP'].src
						found=True
						length=-len(packet['TCP'])
				elif 'UDP' in packet and len(packet['UDP'])>0:
					if packet['UDP'].sport != 53 and packet['UDP'].dport!=53 :
						key = 'UDP:'+packet['IP'].src+' '+str(packet['UDP'].dport)+' '+str(packet['UDP'].sport)
						foreign_ip=packet['IP'].src
						found=True
						length=-len(packet['UDP'])
					else:
						continue			    
			if found and length>0:
				if key in dict:
					if float(packet.time) - float(dict[key]) > float(duration):
						if foreign_ip in new_dict:
							v=new_dict[foreign_ip]
							new_dict[foreign_ip]=v+1
						else:
							new_dict[foreign_ip]=1		
				else:
					if foreign_ip in new_dict:
						v=new_dict[foreign_ip]
						new_dict[foreign_ip]=v+1
					else:
						new_dict[foreign_ip]=1
				dict[key] = float(packet.time)
	for k in new_dict:
		if len(var)==0:
			var=k
		elif new_dict[k]>new_dict[var]:
			var=k
	last_time=0
	for packet in packets:
		if 'IP' in packet and packet['IP'].src == device_ip and packet['IP'].dst == var:
			if float(packet.time)-float(last_time)>float(gap):
				curr = str_timestamp(packet.time-1,-7)
				out.write(curr)
				out.write("\n")
				last_time=float(packet.time)
	out.close()

ip=sys.argv[1]
pcap_file = sys.argv[2]
out_file = sys.argv[3]
gap = sys.argv[4]
dur=sys.argv[5]
get_timestamp(pcap_file,out_file,ip,gap,dur)
