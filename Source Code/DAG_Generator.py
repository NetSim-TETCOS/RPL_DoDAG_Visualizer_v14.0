import pandas as pd
import networkx as nx
import sys
import re
import os
import subprocess
from matplotlib import pyplot as plt

wireshark_install_path = 'C:\\Program Files\\Wireshark\\tshark.exe'
ip_addr = []
node_x = []
node_y = []
color_map = []
labels = []
pos={}

#Function to read Configuration.netsim file and identify node name, Position Coordinates and IP Address
def config_reader(device_id,type,flag):
    device_name=""
    l_flag=0
    if not (os.path.isfile('Configuration.netsim')):
        print("Error: Configuration.netsim file missing in path: "+sys.argv[1])
        exit()
    if "SINKNODE" in type:
        for i, line in enumerate(open('configuration.netsim')):
            try:
                if l_flag==0:
                    found=re.search("<DEVICE KEY=\"GateWay\" DEVICE_NAME=\"(.+?)\" DEVICE_ID=\"(.+?)\" TYPE=\"SINKNODE\" INTERFACE_COUNT=\"2\" DEVICE_ICON=\"(.+?)\">",line).group(1,2)

                    if device_id in found[1]:
                        device_name=found[0]
                        l_flag+=1
                        #print(found)
                else:
                    found=re.search("<POS_3D X_OR_LON=\"(.+?)\" Y_OR_LAT=\"(.+?)\" Z=\"(.+?)\" COORDINATE_SYSTEM=\"(.+?)\" ICON_ROTATION=\"(.+?)\" />",line).group(1,2)
                    #print(found)
                    if flag==1:
                        node_x.append(int(float(found[0])))
                        node_y.append(int(float(found[1])))
                    l_flag+=1                               
                    break

            except AttributeError:
                pass
    elif "SENSOR" in type:
        for i, line in enumerate(open('configuration.netsim')):
            try:
                if l_flag==0:
                    found=re.search("<DEVICE KEY=\"Sensors\" DEVICE_NAME=\"(.+?)\" DEVICE_ID=\"(.+?)\" TYPE=\"(.+?)\" WIRESHARK_OPTION=\"(.+?)\" INTERFACE_COUNT=\"1\" DEVICE_ICON=\"(.+?)\">",line).group(1,2)
                    if device_id in found[1]:
                        device_name=found[0]
                        l_flag+=1
                        #print(found)
                elif l_flag==1:
                    found=re.search("<POS_3D X_OR_LON=\"(.+?)\" Y_OR_LAT=\"(.+?)\" Z=\"(.+?)\" COORDINATE_SYSTEM=\"(.+?)\" ICON_ROTATION=\"(.+?)\">",line).group(1,2)
                    #print(found)
                    if flag==1:
                        node_x.append(int(float(found[0])))
                        node_y.append(int(float(found[1])))
                    l_flag+=1
                else:
                    found=re.search("<PROTOCOL_PROPERTY IP_ADDRESS=\"(.+?)\" PREFIX_LENGTH=\"(.+?)\" DEFAULT_GATEWAY=\"(.+?)\" />",line).group(1,2)
                    ip_addr.append(found[0])
                    #print('IP Address found: '+ip_addr[-1])
                    l_flag+=1
                    break            
                
            except AttributeError:
                pass    
    else:
        print("unknown device type")
    return device_name

#Function to read PCAP file and identify the first calculated Rank value of the node from the DIO message    
def get_rank_from_pcap(filename,flag):
    rank=""
    command = [wireshark_install_path, '-r', filename, '-T', 'fields', '-R', 'icmpv6.code==1', '-Y', 'ipv6.src==' + ip_addr[-1], '-e', 'icmpv6.rpl.dio.rank', '-2']
    output = subprocess.check_output(command, stderr=subprocess.PIPE).decode()
    lines = output.splitlines()
    rank = lines[-1]   
    #print(command)
    #print(rank)
    if(flag==1):
        print("\nRank obtained from the PCAP log: "+str(int(rank)))
    return int(rank)

#Function to create node label based on node name from Configuration file and rank value from PCAP file(if exists)
def get_node_label(type,device,flag):
    node_label=""
    node=""
    if "SINKNODE" in type:
        #found=re.search("SINKNODE-(.+?)",device).group(1)
        found=device.replace("SINKNODE-","")
        #print("sinknode id: "+found)
        node=config_reader(found,"SINKNODE",flag)
        if(flag==1):
            print("\nIdentified "+ node +" in the Configuration file.")
        r=1
        node_label=(node+'(rank:'+str(r)+')')
    elif "SENSOR" in type:
        #found=re.search("SENSOR-(.+?)",device).group(1)
        found=device.replace("SENSOR-","")
        #print("removed prefix "+device)
        #print("sensor id: "+found)
        node=config_reader(found,"SENSOR",flag)
        if(flag==1):
            print("\nIdentified "+ node +" in the Configuration file.")
        r=0
        if(os.path.isfile(node+'_1.pcap')):
            r=get_rank_from_pcap(sys.argv[1]+'\\'+node+'_1.pcap',flag);
            node_label=(node+'(rank:'+str(r)+')')
        else:
            node_label=(node)
    else:
        print("unknown device type")
    return ('\n\n\n'+node_label)

if len(sys.argv) == 1:
   print('Error: No Arguments Passed\nPass the path of the saved IoT-RPL experiment as argument to get the DoDAG Plot.')
   sys.exit()
elif len(sys.argv) >= 2:
    if not(os.path.exists(sys.argv[1])):
        print('Error: Invalid Experiment path. Pass the path of the saved IoT-RPL experiment as argument to get the DoDAG Plot.')
        sys.exit()
if len(sys.argv) == 3:
    if(os.path.exists(sys.argv[2])):
        wireshark_install_path=sys.argv[2]
    else:
        print('Error: Invalid Wireshark Install path.\nContinuing with the default path: '+wireshark_install_path)
   
#print(sys.argv[1])
os.chdir(sys.argv[1])
tracepath = sys.argv[1]+'\Packet Trace.csv'

if not (os.path.isfile(tracepath)):
    print("Error: Packet Trace.csv file missing in path: "+sys.argv[1])
    exit()

#Read Packet Trace log file and identify DAO entries for DoDAG Edges
iter_csv = pd.read_csv(tracepath, usecols=["CONTROL_PACKET_TYPE/APP_NAME","TRANSMITTER_ID","RECEIVER_ID"], iterator=True, chunksize=1000,encoding="iso-8859-1")
df_DAO = pd.concat([chunk[chunk['CONTROL_PACKET_TYPE/APP_NAME'] == "DAO"] for chunk in iter_csv])
df_DAO_1=df_DAO.drop_duplicates()
#print(df_DAO_1)
df_DAO_2=df_DAO_1.drop_duplicates(subset=["TRANSMITTER_ID"],keep='last')
#print(df_DAO_2)
df_DAO_final=df_DAO_2.drop(columns=['CONTROL_PACKET_TYPE/APP_NAME'],axis=1)
print('\nIdentified Entries from the Packet Trace log:\n')
print(df_DAO_final)

G = nx.DiGraph()

#Add nodes and edges to DoDAG plot based on Packet Trace and PCAP file lookup
#Node Color is set to red for 6LowPANGateway and Yellow for sensors

for ind in df_DAO_final.index:

    if "SINKNODE" in df_DAO_final['TRANSMITTER_ID'][ind]:
        source=get_node_label("SINKNODE",df_DAO_final['TRANSMITTER_ID'][ind],0)
    else:
        source=get_node_label("SENSOR",df_DAO_final['TRANSMITTER_ID'][ind],0)
    
    if "SINKNODE" in df_DAO_final['RECEIVER_ID'][ind]:
        target=get_node_label("SINKNODE",df_DAO_final['RECEIVER_ID'][ind],0)
    else:
        target=get_node_label("SENSOR",df_DAO_final['RECEIVER_ID'][ind],0)

    
    if not(G.has_node(source)):
        if "SINKNODE" in df_DAO_final['TRANSMITTER_ID'][ind]:
            color_map.append('red')
            l=get_node_label("SINKNODE",df_DAO_final['TRANSMITTER_ID'][ind],1)
            labels.append(l)
            
        else:
            color_map.append('yellow')
            l=get_node_label("SENSOR",df_DAO_final['TRANSMITTER_ID'][ind],1)
            labels.append(l)
            
        G.add_node(labels[-1])
            
    if not(G.has_node(target)):
        if "SINKNODE" in df_DAO_final['RECEIVER_ID'][ind]:
            color_map.append('red')
            l=get_node_label("SINKNODE",df_DAO_final['RECEIVER_ID'][ind],1)
            labels.append(l)
            
        else:
            color_map.append('yellow')
            l=get_node_label("SENSOR",df_DAO_final['RECEIVER_ID'][ind],1)
            labels.append(l)            
            
        G.add_node(labels[-1])
            
    G.add_edge(source, target,style='dashed')
    #print(df_DAO_final['TRANSMITTER_ID'][ind], df_DAO_final['RECEIVER_ID'][ind])

#print(node_x)
#print(node_y)

for i in range(len(labels)):
    pos[labels[i]]=(node_x[i],node_y[i])

#print(pos)
#print(labels)
#print(color_map)

#Draw DiGraph of RPL DoDAG
fig,ax = plt.subplots()
plt.gcf().canvas.manager.set_window_title("RPL DoDAG Visualization")
nx.draw_networkx(G, pos, node_color=color_map, font_size=8, style='dashed')
ax.invert_yaxis()
plt.tight_layout()
plt.axis('off')
plt.show()



