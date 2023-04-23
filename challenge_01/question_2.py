from xml.etree import ElementTree
import pyshark

coap_code = {'GET': '1', 'POST': '2', 'PUT': '3', 'DELETE': '4'};
coap_response_code = {'NOT_FOUND': '132', 'DELETED': '66'}
coap_type = {'CON': '0', 'NON': '1', 'ACK': '2', 'RST': '3'}; 



#successfully deleted
first_filter = 'coap and coap.code == 66 and coap.type in {1, 2} and ip.src == 134.102.218.18'
first_capture = pyshark.FileCapture('challenge.pcapng', display_filter=first_filter)
ack_mid = set();
non_token = set();

for packet in first_capture:
    if packet.coap.type == coap_type['ACK']:
        ack_mid.add(packet.coap.mid);
    elif packet.coap.type == coap_type['NON'] and hasattr(packet.coap, 'token'):
        non_token.add(packet.coap.token)


print(len(ack_mid) + len(non_token));

second_filter = 'coap and coap.code == 4 and coap.type in {0, 1} and ip.dst == 134.102.218.18'
second_capture = pyshark.FileCapture('challenge.pcapng', display_filter= second_filter)

result_mid = set();
hello_resource_mid = set();
n = 0;
n_hello = 0;

for packet in second_capture:
    if ((packet.coap.type == coap_type['CON'] and packet.coap.mid not in ack_mid) or 
    (packet.coap.type == coap_type['NON'] and hasattr(packet.coap, 'token') and packet.coap.token not in non_token)):
        n+=1;
        if (hasattr(packet.coap, 'opt_uri_path') and packet.coap.opt_uri_path == 'hello'):
            hello_resource_mid.add(packet.coap.mid);
            n_hello += 1;
        else:
            result_mid.add(packet.coap.mid)


#Print results
print(n, n_hello)

# Close the capture file
first_capture.close()
# second_caputure.close()

