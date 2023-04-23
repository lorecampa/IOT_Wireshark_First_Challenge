import pyshark


def areSimilar(t1, t2):
    #assuming that t1 is formatted correctly
    tl1 = t1.split('/');
    tl2 = t2.split('/');

    for i in range(min(len(tl1), len(tl2))):
        if tl1[i] == '#':
            return True;
        if (tl1[i] != '+' and tl1[i] != tl2[i]):
            return False;

    return len(tl1) == len(tl2);



first_filter = 'mqtt and ip.dst ==91.121.93.94  and mqtt.msgtype == 8 and mqtt.topic contains "+"'
first_capture = pyshark.FileCapture('challenge.pcapng', display_filter=first_filter)
clients = set();
for packet in first_capture:
    clients.add((packet.ip.addr, packet.tcp.srcport))

second_filter = 'mqtt and ip.dst == 91.121.93.94 and mqtt.msgtype == 8'
second_capture = pyshark.FileCapture('challenge.pcapng', display_filter=second_filter)
topic = "hospital/room2/area0";
registered_clients = []
for packet in second_capture:
    p_topic = packet.mqtt.topic;
    client = (packet.ip.addr, packet.tcp.srcport);
    if (areSimilar(p_topic, topic) and client in clients):
        registered_clients.append((client, p_topic))

# Print the results
print(clients, registered_clients)



# Close the capture file
first_capture.close()
second_capture.close()


