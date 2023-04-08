import pyshark

first_filter = 'mqtt and mqtt.msgtype == 1 and ip.dst in {3.65.137.17, 52.29.173.150} and mqtt.ver == 5'
first_capture = pyshark.FileCapture('challenge.pcapng', display_filter=first_filter)
clients = set();
for packet in first_capture:
    client = (packet.ip.addr, packet.tcp.srcport);
    clients.add(client);


second_filter = 'mqtt and mqtt.msgtype == 3 and ip.src in {3.65.137.17, 52.29.173.150} and mqtt.qos == 1'
second_capture = pyshark.FileCapture('challenge.pcapng', display_filter=second_filter)

n = 0;
for packet in second_capture:
    client = (packet.ip.dst, packet.tcp.dstport);
    if (client in clients):
        mqtt_layers = packet.layers[3:]
        for mqtt in mqtt_layers:
            if (hasattr(mqtt, 'qos') and mqtt.qos == '1'):
                n += 1;

# Print the results
print(clients, n)



# Close the capture file
first_capture.close()
second_capture.close()


