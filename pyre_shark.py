#!/usr/bin/python
# -*- coding:utf-8 -*-
import sys
from PyQt4.QtGui import *       
from PyQt4.QtCore import *
from PyQt4 import QtGui
from PyQt4 import QtCore
import socket
from struct import *
import datetime
import pcapy
import geoip2.database
from geoip2.errors import *
import threading
# from time import sleep
import time
import subprocess
# import gc
import logging


# gloval value
# dump_file = "sniffer.pcap"
# map_width=723
# map_height=444
# x_greenwich = 65
# y_redline = 275
# reader = geoip2.database.Reader('/usr/local/share/GeoIP/GeoLite2-City.mmdb')
# main_window = ""
s_cap_res = ""
d_cap_res = ""
# worldmapimage = 'world_map.jpg'
# host_addr = ""
# paint_x=0
# scene=""
# item=""
# pixmap=""
# cnt=0
# loopFlag=1
item_addr=0
scene_addr=0

class MainWindow(QWidget):
    
    def __init__(self,parent=None):
        # gc.enable()
        self.loopFlag = 0
        self.map_width=723
        self.map_height=444
        self.x_greenwich = 65
        self.y_redline = 275
        self.reader = geoip2.database.Reader('/usr/local/share/GeoIP/GeoLite2-City.mmdb')
        self.worldmapimage = 'world_map.jpg'
        # self.s_cap_res
        # self.d_cap_res
        self.host_addr=""
        self.counter=0
        self.srcLocationX=None
        self.srcLocationY=None
        self.dstLocationX=None
        self.dstLocationY=None
        
        logging.basicConfig(filename='out_pyreshark.log',level=logging.DEBUG)
        
        
        super(MainWindow,self).__init__()
        self.start_button = QPushButton("Start")
        # self.start_button.clicked.connect(self.write_packet)
        self.start_button.clicked.connect(self.start_capture)

        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_capture)

        # self.textBox = QTextEdit()

        # global scene
        # global pixmap
        # global item_addr
        # global scene_addr
        # global item
        
        self.view = QtGui.QGraphicsView()
        self.view.setSizePolicy(QSizePolicy.Ignored,QSizePolicy.Ignored)
        self.scene = QtGui.QGraphicsScene()
        scene_addr=hex(id(self.scene))
        pixmap = QtGui.QPixmap(self.worldmapimage)
        self.item = QtGui.QGraphicsPixmapItem(pixmap)
        # item = QtGui.QGraphicsPixmapItem(pixmap)
        item_addr=hex(id(self.item))
        # item_addr=hex(id(item))
        self.scene.addItem(self.item)
        # self.scene.addItem(item)
        # self.scene.addLine(0,y_redline,map_width,y_redline,QPen(Qt.red))
        # self.scene.addLine(x_greenwich,0,x_greenwich,map_height,QPen(Qt.blue))
        # self.scene.addLine(345,0,345,map_height,QPen(Qt.black)) #japan_x
        # self.scene.addLine(0,200,map_width,200,QPen(Qt.black)) #japan_y
        # self.viewscene = QtGui.QGraphicsScene()
        self.view.setScene(self.scene)
        # print("scene = "+hex(id(self.scene)))
        # logging.info("scene = "+hex(id(self.scene)))

        self.label1 = QtGui.QLabel("Label1")
        self.label2 = QtGui.QLabel("Label2")
        self.label3 = QtGui.QLabel("Label3")
        self.label4 = QtGui.QLabel("Label4")
        self.label5 = QtGui.QLabel("Label5")
        font = QtGui.QFont()
        font.setPointSize(15)
        self.label1.setFont(font)
        self.label2.setFont(font)
        self.label3.setFont(font)
        self.label4.setFont(font)
        self.label5.setFont(font)
        labelLayout = QVBoxLayout()
        labelLayout.addWidget(self.label1)
        labelLayout.addWidget(self.label2)
        labelLayout.addWidget(self.label3)
        labelLayout.addWidget(self.label4)
        labelLayout.addWidget(self.label5)
        
        buttonLayout = QHBoxLayout()
        buttonLayout.addWidget(self.start_button)
        buttonLayout.addWidget(self.stop_button)
        mapLayout = QHBoxLayout()
        # mapLayout.setSpacing(150)
        mapLayout.addLayout(labelLayout)
        # mapLayout.addWidget(self.textBox)
        mapLayout.addWidget(self.view)
        mainLayout = QVBoxLayout()
        mainLayout.addLayout(mapLayout)
        mainLayout.addLayout(buttonLayout)
        # mainLayout.addWidget(self.textBox)
        # mainLayout.addWidget(self.view)
        
        self.setLayout(mainLayout)
        self.resize(1400,500)
        self.setWindowTitle("ULTRA_ONE_Capture")
        # self.setWindowFlags(Qt.WindowStayOnTopHint())
        self.show()

    def closeEvent(self,event):
        # global loopFlag
        self.loopFlag=0
        # print("close")
        logging.info("close")
        sys.exit(self)
        # sys.exit(1)
    def start_capture(self):
        # global loopFlag
        if self.loopFlag==0:
            self.write_packet()
        self.loopFlag=1
        # print("start")
        logging.info("start")
    def stop_capture(self):
        # global loopFlag
        self.loopFlag=0
        # print("stop")
        logging.info("stop")
        # self.scene.removeItem(self.item)
    def paintEvent(self,event):
        time.sleep(0.1)
        try:
            self.renderLine(self.srcLocationX,self.srcLocationY,self.dstLocationX,self.dstLocationY)
        except:
            print("test")
            pass
    def initMap(self):
        # global cnt
        # global scene
        # print("scene = "+hex(id(self.scene)))
        # print("item = "+hex(id(self.item)))
        # logging.info("scene = "+hex(id(self.scene)))
        # logging.info("item = "+hex(id(self.item)))
        # cnt=cnt+1
        # print("initmap_start")
        logging.info("initmap_start")
        # logging.info("item      = "+str(hex(id(self.item))))
        # logging.info("item_addr = "+str(item_addr))
        # logging.info("scene     = "+str(hex(id(self.scene))))
        # logging.info("scene_addr= "+str(scene_addr))
        self.scene.removeItem(self.item)
        # self.scene.removeItem(item)
        self.counter=self.counter+1
        self.counter=self.counter%10
        if (self.counter == 0):
            self.scene.clear()
            # pass
            # print(self.counter)
            
        logging.info("clear_finished")
        # pixmap = QtGui.QPixmap(self.worldmapimage)
        # item = QtGui.QGraphicsPixmapItem(pixmap)
        # logging.info("item      = "+str(hex(id(self.item))))
        # logging.info("item_addr = "+str(item_addr))
        # logging.info("scene     = "+str(hex(id(self.scene))))
        # logging.info("scene_addr= "+str(scene_addr))
        self.scene.addItem(self.item)
        # self.scene.addItem(item)
        logging.info("additem_finished")
        # self.scene.addLine(0,y_redline,map_width,y_redline,QPen(Qt.red))
        # logging.info("addLine_1")
        # self.scene.addLine(x_greenwich,0,x_greenwich,map_height,QPen(Qt.blue))
        # print("cnt="+str(cnt))
        # gc.collect()
        # logging.info("scene = "+hex(id(self.scene)))
        # logging.info("item = "+hex(id(self.item)))
        logging.info("initmap_finished")

        
    def renderLine(self,src_x,src_y,dst_x,dst_y):
        self.initMap()
        # self.scene.clearSelection()
        # print("gc = "+str(gc.DEBUG_COLLECTABLE))
        logging.info("render_start")
        self.scene.addEllipse(src_x-5,src_y-5,10,10,QPen(Qt.red),QBrush(Qt.red))
        logging.info("render_1")
        self.scene.addEllipse(dst_x-5,dst_y-5,10,10,QPen(Qt.blue),QBrush(Qt.blue))
        logging.info("render_2")
        self.scene.addLine(src_x,src_y,dst_x,dst_y,QPen(Qt.black))
        logging.info("render_finished")
        self.scene.update(0,0,723,444)
        self.update(0,0,1400,500)
        logging.info("update_finished")
        # self.viewscene = self.scene
        # self.view.setScene(self.viewscene)
        logging.info("renderLine_finished")
        self.write_ip()
        logging.info("write_ip_finished")
    # def paintEvent(self,event):
        # global paint_x
        # paint_x = paint_x +1
        # painter = QPainter(self.scene)
        # painter.setPen(Qt.red)
        # painter.setCompositionMode(QPainter.CompositionMode_Xor)
        # painter.drawLine(paint_x,0,800,500)
        # self.scene.addLine(paint_x,0,300,500,QPen(Qt.red))
        # self.initMap()
        
        # print ("paintEvent")

    def setLocation(self,src_x,src_y,dst_x,dst_y):
        self.srcLocationX=src_x
        self.srcLocationY=src_y
        self.dstLocationX=dst_x
        self.dstLocationY=dst_y
        
    def capture_thread(self):
        
        # global s_cap_res
        # global d_cap_res
        logging.info ("Thread Start")
        cap = self.capture_packet(sys.argv)
        while(self.loopFlag):
            logging.info("LoopFlag"+str(self.loopFlag))
            logging.info ("next")
            # logging.info ("scene = "+hex(id(self.scene)))
            # logging.info ("viewscene = "+hex(id(self.viewscene)))
            # logging.info ("item = "+hex(id(self.item)))
            # logging.info ("item = "+hex(id(item)))
            (header,packet) = cap.next()
            # self.initMap()
            logging.info ("parse")
            # try:
            (protocol_type,s_addr,d_addr) = self.parse_packet(packet)
            # cap_res = str(s_addr)+"("+str(get_geoip(s_addr))+")->"+str(d_addr)+"("+str(get_geoip(d_addr))+")"
            logging.info ("res")
            self.s_cap_res = str(protocol_type)+": "+ str(s_addr)+"("+str(self.get_geoip(s_addr)) + ","+str(self.get_geoip_location(s_addr))+")"
            self.d_cap_res = str(d_addr)+"("+str(self.get_geoip(d_addr)) + ","+str(self.get_geoip_location(d_addr))+")"
            # try:
            if self.get_geoip_location(d_addr) != None and self.get_geoip_location(s_addr) != None:
                srcloc = tuple(self.get_geoip_location(s_addr).split(','))
                dstloc = tuple(self.get_geoip_location(d_addr).split(','))
                logging.info("srcloc="+str(srcloc))
                logging.info("dstloc="+str(dstloc))
                srcloc_x = self.mapLocationX(float(srcloc[1]))
                srcloc_y = self.mapLocationY(float(srcloc[0]))
                dstloc_x = self.mapLocationX(float(dstloc[1]))
                dstloc_y = self.mapLocationY(float(dstloc[0]))
                logging.info ("srcX="+str(srcloc_x))
                logging.info ("srcY="+str(srcloc_y))
                logging.info ("dstX="+str(dstloc_x))
                logging.info ("dstY="+str(dstloc_y))
                self.setLocation(srcloc_x,srcloc_y,dstloc_x,dstloc_y)
            else:
                self.setLocation(None,None,None,None)
                # self.renderLine(srcloc_x,srcloc_y,dstloc_x,dstloc_y)
            # except AddressNotFoundError:
                # print("AddressNotFoundError")
                # pass
            # except:
                # print("try-except")
                # pass
            logging.info ("write_packet")
            # self.write_ip()
            logging.info("write_ip_done")
            # except TypeError as e:
            #     print ("typeerror")
            # else:
            #     pass
            # self.update()
            # print("update_finished")
            logging.info("sleep_started")
            # time.sleep(0.5)
            # nowtime=time.clock()
            # while((time.clock()-nowtime) < 0.5):
            #     # print(self.counter)
            #     pass
            logging.info("sleep_ended")
        logging.info("Thread_stop")

    def mapLocationX(self,x):
        if x < 0:
            # x = 180+(180-x)
            x = 360 + x
        x = x*2+self.x_greenwich
        if x > 723:
            x = x - 723
        return x
    def mapLocationY(self,y):
        return self.y_redline-2*y
    def write_packet(self):
        # self.textBox.append(capture_packet(sys.argv))
        # self.start_button.clicked.disconnect(self.write_packet)
        # self.start_button.clicked.connect(self.start_capture)
        client_thread = threading.Thread(target=self.capture_thread,args=())
        client_thread.start()
        
    def write_ip(self):
        # global s_cap_res
        # global d_cap_res
        # print (len(s_cap_res))
        # print (len(d_cap_res))
        # self.textBox.append(self.s_cap_res+" => "+self.d_cap_res+"\n")
        logging.info("test1")
        # self.label5.clear()
        # self.label5.setText(self.label4.text())
        old=self.label4.text()
        self.label5.setText(old)
        logging.info("test2")
        # self.label4.clear()
        # self.label4.setText(self.label3.text())
        old=self.label3.text()
        self.label4.setText(old)
        logging.info("test3")
        # self.label3.clear()
        # self.label3.setText(self.label2.text())
        old=self.label2.text()
        self.label3.setText(old)
        logging.info("test4")
        # self.label2.clear()
        # self.label2.setText(self.label1.text())
        old=self.label1.text()
        self.label2.setText(old)
        logging.info("test5")
        # self.label1.clear()
        old=str(self.s_cap_res)+" \n=> "+str(self.d_cap_res)
        # self.label1.setText(self.s_cap_res+" \n=> "+self.d_cap_res)
        self.label1.setText(old)
        logging.info("write_ip_finished")
        # self.textBox.setText(s_cap_res+" => "+d_cap_res+"\n")
        # self.textBox.append("-"*70)
        # s_cap_res = ""
        # d_cap_res = ""
        # print "write_ip "+cap_res+"\n"

    def get_geoip(self,addr):
        # gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
        # print gi.country_code_by_addr('203.216.243.218')   # www.yahoo.co.jp
        # print (gi.country_code_by_addr(addr))
        # return gi.country_code_by_addr(addr)
        
        # reader = geoip2.database.Reader('/usr/local/share/GeoIP/GeoLite2-City.mmdb')
        try:
            record = self.reader.city(addr)
            logging.info (record.country.name)
            # print (record.country.name+", ("+record.location.latitude+","+record.location.longitude+")")
            # return (record.country.name+", ("+record.location.latitude+","+record.location.longitude+")")
            return record.country.name
        except AddressNotFoundError:
            logging.info ("geoip None")
            # print ("addr="+addr+" self.host_addr="+self.host_addr[2:(len(self.host_addr) -1 )])
            if(str(addr) == self.host_addr):
                return "host"
            else:
                return None
        except:
            return None

    def get_geoip_location(self,addr):
        # reader = geoip2.database.Reader('/usr/local/share/GeoIP/GeoLite2-City.mmdb')
        try:
            record = self.reader.city(addr)
            logging.info (record.location.latitude)
            logging.info (record.location.longitude)
            ip_location = str(record.location.latitude) + "," + str(record.location.longitude)
            return ip_location
        except AddressNotFoundError:
            # if (str(addr) == str(host_addr[2:(len(host_addr) -1)])):
            if(str(addr) == self.host_addr):
                return "35,139"#host_addr
            else:
                return None
        except Exception as e:
            logging.info("Exception_type="+str(type(e)))
            logging.info("Exception="+str(e))
            return None
    # def get_location(self,addr):
    #     try:
    #         record = reader.city(addr)
    #         return record.location.latitude , record.location.longitude
    #     except:
    #         return None,None
        
    def capture_packet(self,argv):
        # global host_addr
        device = pcapy.findalldevs()[0]
        cap = pcapy.open_live(device,65536,True,0)
        # cap.setfilter('tcp')
        self.host_addr = subprocess.check_output("ip a | grep {0}".format(device),shell=True)
        self.host_addr=str(self.host_addr)
        first = self.host_addr.index("inet")+5
        last = self.host_addr.index("brd")-4
        self.host_addr = self.host_addr[first:last]
        # self.host_addr = str(self.host_addr[105:118])
        logging.info ("host_addr="+self.host_addr)
        return cap

    def eth_addr (self,a) :
        # b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(str(a[0])) , ord(str(a[1])) , ord(str(a[2])), ord(str(a[3])), ord(str(a[4])) , ord(str(a[5])))
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(chr(a[0])) , ord(chr(a[1])) , ord(chr(a[2])), ord(chr(a[3])), ord(chr(a[4])) , ord(chr(a[5])))
        return b

    #function to parse a packet
    def parse_packet(self,packet) :
        logging.info ("parse_packet")
        # logging.info ("\n"+str(packet)+"\n")
        # logging.info ("\n"+str(int.from_bytes(packet,'little'))+"\n")
        
        #parse ethernet header
        eth_length = 14
        
        eth_header = packet[:eth_length]
        logging.info("eth_header= "+str(eth_header))
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        logging.info ('Destination MAC : ' + self.eth_addr(packet[0:6]) + ' Source MAC : ' + self.eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))

        logging.info ("before if eth_protocol")
        #Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
            logging.info ("eth_protocol = 8")
            ip_header = packet[eth_length:20+eth_length]
        
            #now unpack them :)
            iph = unpack('!BBHHHBBH4s4s' , ip_header)
        
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
        
            iph_length = ihl * 4
        
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);
        
            logging.info ('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

            # logging.info "test_message"+s_addr
            # return s_addr,d_addr

        
            #TCP protocol
            if protocol == 6 :
                logging.info ("TCP protocol")
                t = iph_length + eth_length
                tcp_header = packet[t:t+20]
            
                #now unpack them :)
                tcph = unpack('!HHLLBBHHH' , tcp_header)
            
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
            
                logging.info ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
            
                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size
            
                #get data from the packet
                data = packet[h_size:]
            
                # logging.info ('Data : ' + data)
                return "TCP",s_addr,d_addr
        
            #ICMP Packets
            elif protocol == 1 :
                logging.info ("ICMP protocol")
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u+4]
            
                #now unpack them :)
                icmph = unpack('!BBH' , icmp_header)
            
                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]
            
                logging.info ('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))
            
                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size
            
                #get data from the packet
                data = packet[h_size:]
            
                # logging.info ('Data : ' + data)
                return "ICMP",s_addr,d_addr
            # return data
 
            #UDP packets
            elif protocol == 17 :
                logging.info ("UDP protocol")
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u+8]
            
                #now unpack them :)
                udph = unpack('!HHHH' , udp_header)
            
                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]
            
                logging.info ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))
            
                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size
            
                #get data from the packet
                data = packet[h_size:]
            
                logging.info ('Data : ' + str(data))

                # return str(s_addr),str(d_addr)
                # logging.info ("test17"+s_addr)
                return "UDP",s_addr,d_addr
            # return data

            else :
                logging.info ('Protocol other than TCP/UDP/ICMP')
                return "Other Protocol="+str(protocol),None,None
            # logging.info
        if eth_protocol == 56710 :
            logging.info ("IPv6")
            ipv6_header = packet[eth_length:40+eth_length]
            logging.info ("ipv6_header_size="+str(len(ipv6_header)))
            ipv6h = unpack("!HHHBB16s16s",ipv6_header)
            s_addr = socket.inet_ntop(socket.AF_INET6,ipv6h[5])
            d_addr = socket.inet_ntop(socket.AF_INET6,ipv6h[6])
            logging.info ("s_addr="+s_addr+" d_addr="+d_addr)
            return "IPv6",s_addr,d_addr
            # return "IPv6",None,None
        if eth_protocol == 1544 :
            logging.info ("ARP")
            arp_header = packet[eth_length:28+eth_length]
            logging.info ("arp_header_size="+str(len(arp_header)))
            arph = unpack('!HHBBH6s4s6s4s',arp_header)
            s_addr = socket.inet_ntoa(arph[6])
            d_addr = socket.inet_ntoa(arph[8])
            logging.info ("0: "+str(arph[0]))
            logging.info ("1: "+str(arph[1]))
            logging.info ("2: "+str(arph[2]))
            logging.info ("3: "+str(arph[3]))
            logging.info ("4: "+str(arph[4]))
            logging.info ("5: "+str(self.eth_addr(arph[5])))
            logging.info ("6: "+str(socket.inet_ntoa(arph[6])))
            logging.info ("7: "+str(self.eth_addr(arph[7])))
            logging.info ("8: "+str(socket.inet_ntoa(arph[8])))
            logging.info ("s_addr="+s_addr+" d_addr="+d_addr)
            return "ARP",s_addr,d_addr
            # return "ARP len="+str(len(arp_header)),None,None
        if eth_protocol == 36488:
            logging.info ("802.1X")
            return "802.1X",None,None
        else:
            logging.info ("unknown protocol="+str(eth_protocol))
            return "UNKNOWN type="+str(eth_protocol),None,None

        # else :
        #     logging.info ("test0 = "+str(socket.ntohs(eth[0]))
        #     logging.info "test1 = "+str(socket.ntohs(eth[1]))
        #     logging.info "test2 = "+str(socket.ntohs(eth[2]))
        #     logging.info "test3 = "+str(socket.ntohs(eth[3]))
            # eth_protocol = 0

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    sys.exit(app.exec_())
