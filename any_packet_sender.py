#!/usr/bin/python

import socket
import sys
import getopt
from struct import *

#global
ip_protocol="tcp"
source_ip="192.168.0.1"
dest_ip="127.0.0.1"
user_data="Hello, how are you"
port=80

def usage():
    print("-h, --help           help")
    print("-t, --tcp            send in tcp protocol")
    print("-u, --udp            send in udp protocol")
    print("-i, --icmp           send in icmp protocol")
    print("-s, --source         source_ip        default 192.168.0.1")
    print("-d, --destination    destination_ip   default 127.0.0.1")
    print("-p, --port           destination_port default port_80")
    print("-m, --message        send message     default Hello, how are you")
    print("-f, --fake           fake sender.fact send packet to fake_ip")
    sys.exit()
def main():
    global ip_protocol
    global source_ip
    global dest_ip
    global port
    global user_data
    fakeFlag=0

    if not len(sys.argv[1:]):
        usage()
    try:
        shortopt="htuis:d:p:m:f:"
        longopt=["help","tcp","udp","icmp","source=","destination=","port=","message=","fake="]
        opts,args = getopt.getopt(sys.argv[1:],shortopt,longopt)
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o,a in opts:
        if o in ("-h","--help"):
            usage()
        elif o in ("-t","--tcp"):
            ip_protocol=socket.IPPROTO_TCP
        elif o in ("-u","--udp"):
            ip_protocol=socket.IPPROTO_UDP
        elif o in ("-i","--icmp"):
            ip_protocol=socket.IPPROTO_ICMP
        elif o in ("-s","--source"):
            source_ip=str(a)
            print("src="+str(a))
        elif o in ("-d","--destination"):
            dest_ip=str(a)
            fact_ip=str(a)
            print("dst="+str(a))
        elif o in ("-p","--port"):
            port=a
            print("port="+str(a))
        elif o in("-m","--message"):
            user_data=a
        elif o in("-f","--fake"):
            fakeFlag=1
            fake_ip=str(a)
            print("fact send="+str(a))
        else:
            assert False,"Unhandled Option"
            usage()

    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
    except:
        print("socket error")
        sys.exit()

    packet=""
    if ip_protocol==socket.IPPROTO_TCP:
        packet=tcp_packet()
        print("Protocol=tcp")
    elif ip_protocol==socket.IPPROTO_UDP:
        packet=udp_packet()
        print("Protocol=udp")
    elif ip_protocol==socket.IPPROTO_ICMP:
        packet=icmp_packet()
        print("Protocol=icmp")
    else:
        print("Protocol has not been specified")
        sys.exit()

    print(packet)
    #Send the packet finally - the port specified has no effect
    if fakeFlag==0:
        s.sendto(packet, (dest_ip , 0 ))    # put this in a loop if you want to flood the target
    else:
        s.sendto(packet, (fake_ip , 0 ))    # put this in a loop if you want to flood the target
        
def checksum(msg):
    # 文字数が奇数のときIndex out of range
    s = 0
    # print(len(msg))
    if len(msg) % 2 == 1:
        msg = msg + "\0".encode('utf-8')
    for i in range(0,len(msg),2):
        w = ord(chr(msg[i])) + (ord(chr(msg[i+1])) << 8 )
        s = s+w
    s = (s>>16) + (s & 0xffff)
    s = s+(s >> 16)
    s= ~s & 0xffff
    return s

def create_ip_header():
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = 54321   #Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = ip_protocol #global
    ip_check = 0    # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton ( dest_ip )
 
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
 
    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    # print(len(ip_header))
    return ip_header

def tcp_packet():
    tcp_packet=""
    ip_header = create_ip_header()
    # tcp header fields
    tcp_source = 1234   # source port
    tcp_dest = 80   # destination port
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons (5840)    #   maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0
 
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
    
    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
    print(len(tcp_header))

    source_address=socket.inet_aton(source_ip)
    dest_address=socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = ip_protocol
    tcp_length=len(tcp_header)+len(user_data)

    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length)
    psh = psh + tcp_header + user_data.encode('utf-8')

    tcp_check = checksum(psh)
    tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
 
    # final full packet - syn packets dont have any data
    tcp_packet = ip_header + tcp_header + user_data.encode('utf-8')
    
    return tcp_packet
def udp_packet():
    udp_packet=""
    ip_header = create_ip_header()
    udp_source=1234
    udp_dest=80
    udp_len=8+len(user_data)
    udp_check=0

    udp_header = pack('!HHHH',udp_source,udp_dest,udp_len,udp_check)
    source_address=socket.inet_aton(source_ip)
    dest_address=socket.inet_aton(dest_ip)
    placeholder=0
    protocol=ip_protocol
    udp_length=len(udp_header)+len(user_data)
    
    psh = pack('!4s4sBBH',source_address,dest_address,placeholder,protocol,udp_length)
    psh = psh + udp_header + user_data.encode('utf-8')

    udp_check=checksum(psh)
    udp_header = pack('!HHHH',udp_source,udp_dest,udp_len,udp_check)
    udp_packet = ip_header + udp_header + user_data.encode('utf-8')
    return udp_packet
    
    
def icmp_packet():
    icmp_packet=""
    ip_header = create_ip_header()
    icmp_type=8
    icmp_code=0
    icmp_check=0
    icmp_id=0
    icmp_seq=0
    icmp_header = pack("!BBHHH",icmp_type,icmp_code,icmp_check,icmp_id,icmp_seq)

    source_address=socket.inet_aton(source_ip)
    dest_address=socket.inet_aton(dest_ip)
    placeholder=0
    protocol=ip_protocol
    icmp_length=len(icmp_header)+len(user_data)

    psh = pack('!4s4sBBH',source_address,dest_address,placeholder,protocol,icmp_length)
    psh = psh + icmp_header + user_data.encode('utf-8')
    icmp_check = checksum(psh)
    icmp_header = pack("!BBHHH",icmp_type,icmp_code,icmp_check,icmp_id,icmp_seq)
    icmp_packet = ip_header + icmp_header + user_data.encode('utf-8')
    return icmp_packet
    
if __name__ == '__main__':
    main()
