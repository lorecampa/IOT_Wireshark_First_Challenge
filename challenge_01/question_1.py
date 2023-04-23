import pyshark

coap_code = {'GET': '1', 'POST': '2', 'PUT': '3', 'DELETE': '4'};
coap_response_code = {'NOT_FOUND': '132'}
coap_type = {'CON': '0', 'NON': '1', 'ACK': '2', 'RST': '3'}; 

# Iterate through each packet in the capture file
ack_mid = []
non_tokens = []
first_filter = 'coap and ip.src == 127.0.0.1 and coap.code == 132 and coap.type in {1, 2}'
first_capture = pyshark.FileCapture('challenge.pcapng', display_filter=first_filter)
for packet in first_capture:
    if (packet.coap.type == coap_type['ACK']):
        ack_mid.append(packet.coap.mid)
    elif (packet.coap.type == coap_type['NON'] and hasattr(packet.coap, 'token')):
        non_tokens.append(packet.coap.token);

second_filter = 'coap and ip.dst == 127.0.0.1 and coap.code == 1 and coap.type in {0, 1}'
second_caputure = pyshark.FileCapture('challenge.pcapng', display_filter=second_filter)
con_mid = []
non_mid = []
for packet in second_caputure:
    if packet.coap.mid in ack_mid:
        con_mid.append(packet.coap.mid);
    elif hasattr(packet.coap, 'token') and packet.coap.token in non_tokens:
        non_mid.append(packet.coap.mid)



# Print the results
print(len(con_mid) + len(non_mid), 'CON:', con_mid, 'NON:', non_mid)

# Close the capture file
first_capture.close()
second_caputure.close()
