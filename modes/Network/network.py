from flask import Flask, render_template, request, redirect, url_for
from scapy.all import sniff, send, IP, ICMP, wrpcap, rdpcap
import binascii
import os
import os
from flask import Blueprint, current_app, render_template, url_for, redirect, request, session, flash
from datetime import timedelta
#from flask_wtf import FlaskForm
#from werkzeug.utils import secure_filename

network = Blueprint("network", __name__, static_folder="static",
                 template_folder="templates")

import binascii

#conf.verb = 2  # Set Scapy verbosity level
#conf.iface = "wi-fi"  # Set the network interface

#app = Flask(__name__)
@network.route('/encode', methods=['POST' , 'GET'])
def encode():
    encoded_message = None  # Initialize encoded message variable
    if request.method == 'POST':
        message = request.form['message']
        encoded_message = encode_message(message)
        transmit_encoded_message(encoded_message)
    return render_template('encode-home.html', encoded_message=encoded_message)

#@network.route('/encode', methods=['POST' , 'GET'])
#def encode():
 #   if request.method == 'POST':
  #      message = request.form['message']
   #     encoded_message = encode_message(message)
    #    transmit_encoded_message(encoded_message)
     #   return render_template('encode-home.html' )
    #result = request.form
    #return render_template('encode-home.html' , encoded_message=encoded_message)#,# result=result)
    

@network.route('/decode', methods=['POST', 'GET'])
def decode():
    if request.method == 'POST':
        captured_packets = capture_packets()  # Capture packets with TTL information
        decoded_message = decode_message(captured_packets)
        return render_template('decode-home.html', decoded_message=decoded_message)
    result = request.form
    return render_template('decode-home.html' , result=result)

def encode_message(message):
    # Convert each character to its binary representation and concatenate them
    bin_data = [bin(ord(char))[2:].zfill(8) for char in message]
    encoded_message = ''.join(bin_data)
    return encoded_message
'''
def transmit_encoded_message(encoded_message):
    for chunk in [encoded_message[i:i+8] for i in range(0, len(encoded_message), 8)]:
        for bit_pair in [chunk[i:i+2] for i in range(0, len(chunk), 2)]:
            ttl_value = int(bit_pair + '11', 2)
            packet = IP(src='192.168.10.41', dst='10.0.2.15') / ICMP()
            packet.ttl = ttl_value
            ttl_value = 63
            packet.show()  # Display the packet for debugging
            # Send packet
            send(packet, verbose=False)'''

def transmit_encoded_message(encoded_message):
    # Construct the base packet
    base_packet = IP(src='192.168.10.41', dst='10.0.2.15') / ICMP()
    
    # Iterate over encoded message and send packets
    for chunk in [encoded_message[i:i+8] for i in range(0, len(encoded_message), 8)]:
        for bit_pair in [chunk[i:i+2] for i in range(0, len(chunk), 2)]:
            ttl_value = int(bit_pair + '11', 2)
            base_packet.ttl = ttl_value  # Set TTL value
            base_packet.show()  # Display the packet for debugging
            # Send packet
            send(base_packet, verbose=False)


def capture_packets():
    # Capture packets with TTL information
    packets = sniff(timeout=60, filter="icmp")
    # Write captured packets to a pcap file for analysis
    wrpcap("captured_packets.pcap", packets)
    return packets
def decode_message(packets):
    msg = []
    for packet in packets:
        try:
            msg.append(packet[IP].ttl)
        except AttributeError:
            # Handle the case where the packet does not contain TTL attribute
            print("Warning: Packet does not contain TTL attribute.")
            continue
        except Exception as e:
            # Handle any other unexpected exceptions
            print("Error decoding packet:", e)
            continue

    if not msg:
        print("No TTL attributes found in any packet.")
        return "No TTL attributes found in any packet."

    # Join the TTL values and convert the binary string to text
    binary_string = ''.join(['{:08b}'.format(i)[:6] for i in msg])
    decoded_message = ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))
    return decoded_message

'''#def decode_message(packets):
 #   msg = []
    for packet in packets:
        try:
            msg.append(packet[IP].ttl)
        except AttributeError:
            print("Warning: Packet does not contain TTL attribute.")
            continue
    if not msg:
        print("No TTL attributes found in any packet.")
        return "No TTL attributes found in any packet."

    # Join the TTL values and convert the binary string to text
    binary_string = ''.join(['{:08b}'.format(i)[:6] for i in msg])
    decoded_message = ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))
    return decoded_message'''


''''

#conf.verb = 2  # Set Scapy verbosity level
#conf.iface = "wi-fi"  # Set the network interface

app = Flask(__name__)

#@network.route('/home')
#def home():
 #   return render_template('home.html')

@network.route('/encode', methods=['POST', 'GET'])
def encode():
    if request.method == 'POST':
        message = request.form['message']
        encoded_message = encode_message(message)
        transmit_encoded_message(encoded_message)
        return render_template('encode-home.html', encoded_message=encoded_message)
    return render_template('encode-home.html')

@network.route('/decode', methods=['POST', 'GET'])
def decode():
    if request.method == 'POST':
        captured_packets = capture_packets()  # Capture packets with TTL information
        decoded_message = decode_message(captured_packets)
        return render_template('decode-home.html', decoded_message=decoded_message)
    return render_template('decode-home.html')

def encode_message(message):
    # Convert each character to its binary representation and concatenate them
    bin_data = [bin(ord(char))[2:].zfill(8) for char in message]
    encoded_message = ''.join(bin_data)
    return encoded_message

def transmit_encoded_message(encoded_message):
    for chunk in [encoded_message[i:i+8] for i in range(0, len(encoded_message), 8)]:
        for bit_pair in [chunk[i:i+2] for i in range(0, len(chunk), 2)]:
            ttl_value = int(bit_pair + '11', 2)
            packet = IP(src='192.168.10.41', dst='10.0.2.15') / ICMP()
            packet.ttl = ttl_value
            packet.show()  # Display the packet for debugging
            # Send packet
            send(packet, verbose=False)

def capture_packets():
    # Capture packets with TTL information
    packets = sniff(timeout=60, filter="icmp")
    # Write captured packets to a pcap file for analysis
    wrpcap("captured_packets.pcap", packets)
    return packets

def decode_message(packets):
    msg = []
    for packet in packets:
        try:
            msg.append(packet[IP].ttl)
        except AttributeError:
            print("Warning: Packet does not contain TTL attribute.")
            continue
    if not msg:
        print("No TTL attributes found in any packet.")
        return "No TTL attributes found in any packet."

    # Join the TTL values and convert the binary string to text
    binary_string = ''.join(['{:08b}'.format(i)[:6] for i in msg])
    decoded_message = ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))
    return decoded_message

if __name__ == '__main__':
    app.run(debug=True)'''




