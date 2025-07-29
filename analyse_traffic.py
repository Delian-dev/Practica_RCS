from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
import ipaddress
from datetime import datetime
import json


def readCapture(filepath):
    capture=PcapReader(filepath)
    return list(capture)

def getCaptureSize(capture):
    cnt=0
    for packet in capture:
        cnt=cnt+1
    
    return cnt

def showPacketsData(capture):
    for packet in capture:
        if IP in packet:
            print(f"IPv4: {packet[IP].src} → {packet[IP].dst}")
        elif IPv6 in packet:
            print(f"IPv6: {packet[IPv6].src} → {packet[IPv6].dst}")
        ts=packet.time
        readable_time = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
        print(readable_time)
        print(len(packet))
        print(packet.summary())
        # if packet.haslayer(UDP):
        #     print(packet[UDP].sport)
        print('------------------------------------------------')

def processAudio(capture,idx):
    timestamp = capture[idx].time
    timestamp = datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")

    while idx<noOfPackets:
        packet=capture[idx]
        if len(packet)<80 and capture[idx+1].haslayer(TCP): #seems like len=76/77 for the last QUIC packet
            break

        idx=idx+1
    
    return timestamp,idx

def identifyCallType(capture, idx):
    msgType='audio'
    timestamp = capture[idx].time
    timestamp = datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
    while idx<noOfPackets:
        packet=capture[idx]
        if packet.haslayer(UDP):
            if len(packet)>1000 and packet[IP].dport==3478 and msgType=='audio':
                msgType='video'

            #checks message end (3 - 332 len packets, each on a different tcp stream)
            if len(packet)==332 and len(capture[idx+1])==332 and len(capture[idx+2])==332:
                if packet[IP].dst != capture[idx+1][IP].dst and packet[IP].dst != capture[idx+2][IP].dst:
                    idx=idx+2
                    break

        idx=idx+1

    return msgType,timestamp,idx

def processLocation(capture, idx):
    timestamp = capture[idx].time
    timestamp = datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")

    final_api_req=idx #here I will save the last index in the list where an external request to maps was made
                       #for now this logic assumes there isnt more than one share location in the capture
                        #another way would be to simply check if there is a big break between packages but im not really sure now how effective it would be
    while idx<noOfPackets:
        packet=capture[idx]
        if DNS in packet and packet[DNS].qd is not None:
            query = packet[DNS].qd.qname.decode()
            if "maps.googleapis.com" in query:
                final_api_req=idx
        idx=idx+1

    #now, after the last request, I will find the moment in the stream where we have an 'F' flag (FIN), 
    # meaning that we are closing the last connection related to the maps request
    idx=final_api_req
    while idx<noOfPackets:
        packet=capture[idx]
        if TCP in packet:
            tcp_flags = packet[TCP].flags
            if 'F' in tcp_flags: #FIN flag set
                break
        idx=idx+1

    return timestamp,idx


def checkTCPMessageType(capture, idx):
    timestamp = capture[idx].time
    timestamp = datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")

    #basically I try to check for 3 scenarios: Simple text, Media(photo/video/document), or none (method was triggered by a non-message tcp packet)
    #problem is txt/photos/documents all come in packages of size 1446 max
    #its also hard to find a pattern for when I should break from this method
    msgType='none'
    bigPackCounter=0 #havent seen a single text message to take more than 5 packages of 1446 (not really a good criteria ig since small photos/docs can also have a small no of big packages)
                     #still dont know when to break
    while idx<noOfPackets:
        packet=capture[idx]
        if len(packet)>10000: #idk how but for video I have packets of size 10048 => easy way to tell its media
            msgType='Media'

        if len(packet)==1446:
            bigPackCounter=bigPackCounter+1
        
        idx=idx+1


    #after leaving while by some criteria - maybe check when appears a new tcp stream
    if msgType=='none':
        if bigPackCounter>5:
            msgType='Media'
        elif bigPackCounter>=1: #a short text message might have 0 packets so it isnt really good
            msgType='Text'

        #else we consider it none
    
    return msgType,timestamp,idx

def startAnalysis(capture):
    idx=0

    #location_subnet = ipaddress.IPv4Network("142.251.208.0/24")

    while idx<noOfPackets:
        packet=capture[idx]
        if packet.haslayer(UDP):
            if packet[UDP].sport==3478 or packet[UDP].dport==3478:
                #mesaj tip apel audio/video
                callType,timestamp,idx=identifyCallType(capture,idx)

                if callType=='audio':
                    print(f'Message type: Audio Call at {timestamp}') #add this to a json output
                    info={
                        "timestamp": timestamp,
                        "type": 'Audio Call'
                    }
                    output.append(info)
                else:
                    print(f'Message type: Video Call at {timestamp}')
                    info={
                        "timestamp": timestamp,
                        "type": 'Video Call'
                    }
                    output.append(info)
            
            elif packet[UDP].dport==443 and IP in packet and len(packet)>1000: #seems like QUIC (udp 443) on IPV4 (Client->Server) appears only for audio messages
                    timestamp, idx = processAudio(capture,idx)
                    print(f'Message type: Audio Message at {timestamp}')
                    info={
                        "timestamp": timestamp,
                        "type": 'Audio Message'
                    }
                    output.append(info)
            
            else:
                if DNS in packet and packet[DNS].qd is not None:
                    query = packet[DNS].qd.qname.decode()
                    if "maps.googleapis.com" in query:
                        timestamp, idx = processLocation(capture, idx)
                        print(f'Message type: Share Location at {timestamp}')
                        info={
                            "timestamp": timestamp,
                            "type": 'Share Location'
                        }
                    output.append(info)
        
        '''for now this tcp logic doesnt really work and every capture is seen as text/media'''
        #else:
            # if packet.haslayer(TCP):
            #     if packet[TCP].dport==443: #the message packets are mostly client->server
            #         type,timestamp,idx = checkTCPMessageType(capture,idx)
            #         if type != 'none':
            #             print(f'Message type: {type} at {timestamp}' )
            #             info={
            #                 "timestamp": timestamp,
            #                 "type": type
            #             }
            #             output.append(info)
        idx=idx+1



capture=readCapture('../MesajAudio->Tata.pcap') #file to analyze (for now static)

noOfPackets=getCaptureSize(capture)
output=[]
#showPacketsData(capture)
startAnalysis(capture)

#json file:
with open('message_types.json', 'w') as f:
    json.dump(output, f, indent=4)