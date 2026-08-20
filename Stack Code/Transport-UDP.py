# transport.py
# Contains the VirtualUDP class, our virtual Transport Layer.

import json
import zlib
import random
from collections import deque

class VirtualUDP:
    def __init__(self, network_layer):
        self.network_layer = network_layer
        # Register our receiving function with the network layer
        self.network_layer.set_data_callback(self._receive_from_network)
        
        # A dictionary to map port numbers to application callback functions
        self.bound_ports = {}
        # A dictionary of queues, one for each bound port, to hold incoming data
        self.receive_queues = {}

        print(f"[{self.network_layer.my_ip}] Virtual Transport Layer (UDP) initialized.")

# In transport.py

    # =================================================================
    #  >>> REPLACE THIS ENTIRE FUNCTION <<<
    # =================================================================
    def bind(self, port, callback=None): # Added callback for future, but not used now
        """Allows an application to 'listen' on a virtual port."""
        if port not in self.bound_ports:
            # Create the queue for this port
            self.receive_queues[port] = deque(maxlen=100) 
            
            # <<< THIS IS THE FIX >>>
            # Actually register the port as bound. We can store the callback or just a placeholder.
            self.bound_ports[port] = callback if callback is not None else True
            
            print(f"[Transport Layer] Port {port} is now bound.")

    def sendto(self, dest_ip, dest_port, payload, source_port=None):
        """Public API for the Application to send data."""
        if source_port is None:
            source_port = random.randint(49152, 65535) # Use an ephemeral port

        payload_bytes = payload.encode('utf-8')

        # Create the virtual UDP header
        udp_header = {
            "src_port": source_port,
            "dst_port": dest_port,
            "length": 8 + len(payload_bytes), # 8 bytes for a typical UDP header
            "checksum": zlib.crc32(payload_bytes)
        }

        # The payload for the network layer is the combination of our header and the app data
        transport_payload = {
            "udp_header": udp_header,
            "data": payload
        }
        
        # Send the payload down to the network layer
        self.network_layer.send(dest_ip, json.dumps(transport_payload))

    def recvfrom(self, port, max_size=1024):
        """Public API for the Application to receive data from a bound port."""
        if port in self.receive_queues and self.receive_queues[port]:
            # Retrieve the oldest message from the queue for this port
            return self.receive_queues[port].popleft()
        return None, None # Return None if no data is available

    def _receive_from_network(self, source_ip, network_payload):
        """Callback function that the Network layer calls with new data."""
        try:
            transport_packet = json.loads(network_payload)
            header = transport_packet.get("udp_header", {})
            data = transport_packet.get("data", "")
            
            dest_port = header.get("dst_port")

            # Check if any application is listening on this port
            if dest_port in self.bound_ports:
                # Verify checksum
                checksum_received = header.get("checksum")
                checksum_calculated = zlib.crc32(data.encode('utf-8'))

                if checksum_received == checksum_calculated:
                    # Checksum is valid. Deliver the data to the correct queue.
                    source_port = header.get("src_port")
                    self.receive_queues[dest_port].append(((source_ip, source_port), data))
                else:
                    print(f"[Transport Layer] Checksum mismatch! Dropping packet from {source_ip}.")

        except (json.JSONDecodeError, TypeError):
            # Ignore malformed transport packets
            pass