from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSRR
import ipaddress
from datetime import datetime
import json
import re
import glob, os

import gui


def readCapture(filepath):
    capture=PcapReader(filepath)
    return list(capture)

def getCaptureSize(capture):
    cnt=0
    for packet in capture:
        cnt=cnt+1
    
    return cnt

def showPacketsData(capture): #this just helps me to see the package content - not used in the app
    i=0
    for packet in capture:
        if IP in packet:
            print(f"IPv4 {i}: {packet[IP].src} → {packet[IP].dst}")
        elif IPv6 in packet:
            print(f"IPv6: {packet[IPv6].src} → {packet[IPv6].dst}")
        ts=packet.time
        readable_time = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
        print(readable_time)
        print(len(packet))
        print(packet.summary())
        # if packet.haslayer(UDP):
        #     print(packet[UDP].sport)
        i=i+1
        # if i==21:
        #     break
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

    final_api_req=idx #here I will save the last index in the list where an external request to maps was made - OBSOLETE METHOD
                      
    while idx<noOfPackets:
        packet=capture[idx]
        if DNS in packet:
            if packet[DNS].qd is not None:
                query = packet[DNS].qd.qname.decode()
                if "maps.googleapis.com" in query:
                    final_api_req=idx
            
            if packet[DNS].an is not None:
                rr = packet[DNS].an
                ipv4_cnt = 0
                while isinstance(rr, DNSRR): #more than one answer -> seems like the end
                    if rr.type==1: #A record aka ipv4 address
                        ipv4_cnt+=1
                    rr=rr.payload
                
                if ipv4_cnt>1:
                    #print(f"Share location request end")
                    idx=idx+1
                    break

                # if isinstance(rr, DNSRR) and rr.type == 1:  # type=1 meaning IPV4 address (A record)
                #     ipv4_addr = rr.rdata
                #     print(f"Share location request end: {ipv4_addr}")
                #     idx=idx+1
                #     break
            

        idx=idx+1

    # #now, after the last request, I will find the moment in the stream where we have an 'F' flag (FIN), 
    # # meaning that we are closing the last connection related to the maps request
    # idx=final_api_req
    # while idx<noOfPackets:
    #     packet=capture[idx]
    #     if TCP in packet:
    #         tcp_flags = packet[TCP].flags
    #         if 'F' in tcp_flags: #FIN flag set
    #             break
    #     idx=idx+1

    return timestamp,idx


#DIMENSIUNILE PE CARE M-AM BAZAT MAI JOS SUNT PENTRU CAPTURI DE PE LAPTOP - pe telefon par sa difere
def checkTCPMessageType(capture, idx):
    timestamp = capture[idx].time
    timestamp = datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")

    #basically I try to check for 3 scenarios: Simple text, Media(photo/video/document), or none (method was triggered by a non-message tcp packet)
    msgType='none'
    bigPackCounter=0 #havent seen a single text message to take more than 5 packages of 1446 (not really a good criteria ig since small photos/docs can also have a small no of big packages)
                 
    while idx<noOfPackets:
        packet=capture[idx]
        if len(packet)>10000: #idk how but for video I have packets of size 10048 => easy way to tell its media
            msgType='Media'

        if len(packet)==1446: #problem - sometimes instead of more 1446 packets, they are sent as a single bigger package
            bigPackCounter=bigPackCounter+1
        
        if len(packet)<200 and '192.168' not in packet[IP].src and len(packet)!=66: #small package not coming from client (logic still has flaws since there can be small packages between the big ones)
                                                                                    #this might trick the program there are more text messages
            idx=idx+1
            break

        idx=idx+1


    if msgType=='none':
        if bigPackCounter>5:
            msgType='Media'
        elif bigPackCounter>=1: #a short text message might have 0 packets so it isnt really good
            msgType='Text'

        #else we consider it none
    
    return msgType,timestamp,idx

def startAnalysis(capture):
    idx=0


    while idx<noOfPackets:
        packet=capture[idx]
        if packet.haslayer(UDP):
            if packet[UDP].sport==3478 or packet[UDP].dport==3478:
                #mesaj tip apel audio/video
                print(f'{idx} inainte apel')
                print(packet)
                callType,timestamp,idx=identifyCallType(capture,idx)
                print(f'{idx} dupa apel')
                if callType=='audio':
                    print(f'Message type: Audio Call at {timestamp}') #add this to a json output
                    info={
                        "timestamp": timestamp,
                        "type": 'Audio Call'
                    }
                    output[file_key].append(info)
                
                else:
                    print(f'Message type: Video Call at {timestamp}')
                    info={
                        "timestamp": timestamp,
                        "type": 'Video Call'
                    }
                    output[file_key].append(info)
            
            elif packet[UDP].dport==443 and IP in packet: #seems like QUIC (udp 443) on IPV4 (Client->Server) appears only for audio messages (simetimes for calls idk why)
                    print(f'{idx} inainte mesaj audio')
                    print(packet)
                    timestamp, idx = processAudio(capture,idx)
                    print(f'{idx} dupa mesaj audio')
                    print(f'Message type: Audio Message at {timestamp}')
                    info={
                        "timestamp": timestamp,
                        "type": 'Audio Message'
                    }
                    output[file_key].append(info)
            
            else:
                if DNS in packet and packet[DNS].qd is not None:
                    query = packet[DNS].qd.qname.decode()
                    pattern = r"^clients\d+\.google\.com.$"
                    if re.match(pattern,query): #check if simply there is a request to google
                        print(f'{idx} inainte share')
                        print(packet)
                        timestamp, idx = processLocation(capture, idx)
                        print(f'{idx} dupa share')
                        print(f'Message type: Share Location at {timestamp}')
                        info={
                            "timestamp": timestamp,
                            "type": 'Share Location'
                        }
                        output[file_key].append(info)
        
        #for now this tcp logic doesnt really work
        else:
            if packet.haslayer(TCP):
                if packet[TCP].dport==443: #the message packets are mostly client->server
                    #print(len(packet))
                    if len(packet)>=1446:
                        print(f'{idx} inainte mesaj tcp')
                        print(packet)
                        type,timestamp,idx = checkTCPMessageType(capture,idx)
                        print(f'{idx} dupa mesaj tcp')
                        if type != 'none':
                            #print(f'Message type: {type} at {timestamp}' )
                            info={
                                "timestamp": timestamp,
                                "type": type
                            }
                            output[file_key].append(info)
                    
                    #tried to check the cases of short text messages (single packet of larget dimension) - idk how
                    #elif len(packet)==1429 or len(packet)==649 or len(packet)==633 or len(packet)==839:

        idx=idx+1



if __name__ == "__main__":

    filepath, folder_mode = gui.start_gui() #starts the main gui
    #print(filepath)
    # if filepath:
    #     capture = readCapture(filepath)
        
    #     noOfPackets=getCaptureSize(capture)
        
    #     output = {}
    #     file_key = os.path.basename(filepath)  # current file (for now I analyse a single one anyway)
    #     output[file_key] = []
    #     #showPacketsData(capture)
    #     startAnalysis(capture)

    if filepath:
        print(filepath)
        output={}

        if folder_mode:
            pcap_files = glob.glob(os.path.join(filepath, "*.pcap")) + glob.glob(os.path.join(filepath, "*.pcapng"))

            for pcap_file in pcap_files:
                print(f"Processing: {pcap_file}")
                capture = readCapture(pcap_file)
                noOfPackets = getCaptureSize(capture)
                file_key = os.path.basename(pcap_file)

                output[file_key]= []
                #showPacketsData(capture)
                startAnalysis(capture)

        else:
            capture = readCapture(filepath)
            noOfPackets = getCaptureSize(capture)
            file_key = os.path.basename(filepath)

            output[file_key]= []
            #showPacketsData(capture)
            startAnalysis(capture)


        #json file:
        with open('message_types.json', 'w') as f:
            json.dump(output, f, indent=4)
        
        print()
        print("Analysis complete. Output written to message_types.json")
    else:
        print("No folder/file selected")
