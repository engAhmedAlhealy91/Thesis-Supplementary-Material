import socket
import time
import threading
import json
from datetime import datetime
import heapq
import logging
import os # Added for file operations

ISOLATION_RULES = {
    '192.168.10.1': ['192.168.10.3', '192.168.10.4', '192.168.10.5'],
    '192.168.10.2': ['192.168.10.5'],
    '192.168.10.3': ['192.168.10.1'],
    '192.168.10.4': ['192.168.10.1', '192.168.10.5'],
    '192.168.10.5': ['192.168.10.1', '192.168.10.2', '192.168.10.4']
}

class OlsrNode:
    def __init__(self, my_ip, expected_sym_neighbors, is_gateway=False, virtual_interfaces=None, hna_networks=None, olsr_port=698, broadcast_ip='192.168.10.255'):
        self.my_ip = my_ip
        self.port = olsr_port
        self.broadcast_ip = broadcast_ip
        self.my_blacklist = ISOLATION_RULES.get(my_ip, [])
        
        # --- CORRECTED INITIALIZATION ORDER ---
        # Loggers and metric counters must be set up BEFORE they are used.
        self.expected_sym_neighbors = expected_sym_neighbors
        self._neighbor_discovery_complete = False
        self.control_traffic_counts = {'HELLO': 0, 'TC': 0, 'HNA': 0, 'MID': 0}
        self.data_traffic_counts = {'DATA_SENT': 0, 'DATA_FORWARDED': 0, 'DATA_RECEIVED': 0}
        self._setup_loggers()

        # Timers
        self.hello_interval = 2.0
        self.tc_interval = 5.0
        self.hna_interval = 5.0
        self.mid_interval = 5.0
        self.routing_table_interval = 5.0
        self.neighbor_hold_time = self.hello_interval * 3
        self.topology_hold_time = self.tc_interval * 3
        self.hna_hold_time = self.hna_interval * 3
        self.mid_hold_time = self.mid_interval * 3
        self.two_hop_hold_time = self.neighbor_hold_time * 2
        self.mpr_calculation_interval = 5.0
        # Config & Sequence Numbers
        self.willingness = 3
        self.packet_seq_num = 0
        self.hello_message_seq_num = 0
        self.tc_message_seq_num = 0
        self.hna_message_seq_num = 0
        self.mid_message_seq_num = 0
        # Data Structures
        self.table_lock = threading.RLock()
        self.neighbor_table = {}
        self.two_hop_table = {}
        self.mpr_set = set()
        self.mpr_selector_set = set()
        self.topology_table = {}
        self.routing_table = {}
        self.is_gateway = is_gateway
        self.hna_networks = hna_networks if hna_networks else []
        self.hna_table = {}
        self.virtual_interfaces = virtual_interfaces if virtual_interfaces else []
        self.interface_association_table = {}
        self.last_tc_seq_nums = {}
        self.last_hna_seq_nums = {}
        self.last_mid_seq_nums = {}

        # New for Throughput measurement
        self.receiving_files = {} # {'file_id': {'received_chunks': {}, 'total_chunks': 0, 'start_time': 0, 'file_size_bytes': 0, 'current_path': []}}
        self.file_transfer_counter = 0 # To generate unique file IDs

        print(f"[{self.my_ip}] OLSR Node initialized. Logging to olsr_log_{self.my_ip}.txt and pdr_results_{self.my_ip}.csv")

    def _setup_loggers(self):
        self.general_logger = logging.getLogger(f'general_{self.my_ip}')
        self.general_logger.setLevel(logging.INFO)
        if not self.general_logger.handlers:
            fh_general = logging.FileHandler(f'olsr_log_{self.my_ip}.txt', mode='w')
            formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(message)s', datefmt='%H:%M:%S')
            fh_general.setFormatter(formatter)
            self.general_logger.addHandler(fh_general)
        
        # --- Data Logger ---
        self.data_logger = logging.getLogger(f'data_{self.my_ip}')
        self.data_logger.setLevel(logging.INFO)
        if not self.data_logger.handlers:
            fh_data = logging.FileHandler(f'pdr_results_{self.my_ip}.csv', mode='w')
            self.data_logger.addHandler(fh_data)
            
            # <<< UPDATED HEADER for PDR and Throughput data >>>
            self.data_logger.info("EventType,FileID,PacketID,Timestamp,Source,Destination,DelaySec,Path,FileSizeMB,ThroughputMbps")

    def start(self):
        self.general_logger.info(f"NODE_START,ip={self.my_ip}")
        threads = [
            threading.Thread(target=self._hello_sender_thread, daemon=True, name="HelloSender"),
            threading.Thread(target=self._tc_sender_thread, daemon=True, name="TCSender"),
            threading.Thread(target=self._receiver_thread, daemon=True, name="Receiver"),
            threading.Thread(target=self._mpr_selection_thread, daemon=True, name="MPRSelector"),
            threading.Thread(target=self._routing_table_thread, daemon=True, name="RoutingCalculator"),
            threading.Thread(target=self._cleanup_thread, daemon=True, name="Cleanup")
        ]
        if self.is_gateway: threads.append(threading.Thread(target=self._hna_sender_thread, daemon=True, name="HNASender"))
        if self.virtual_interfaces: threads.append(threading.Thread(target=self._mid_sender_thread, daemon=True, name="MIDSender"))
        for t in threads:
            t.start()
        print(f"[{self.my_ip}] Node is running. All threads started. Press Ctrl+C to stop.")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            self.general_logger.info(f"CONTROL_TRAFFIC,{json.dumps(self.control_traffic_counts)}")
            self.general_logger.info(f"DATA_TRAFFIC,{json.dumps(self.data_traffic_counts)}")
            print(f"\n[{self.my_ip}] Shutdown signal received. Exiting.")

    # =================================================================
    #  >>> RESTORED HELPER FUNCTIONS AND SENDER THREADS <<<
    # =================================================================
    def _broadcast(self, packet_bytes):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender_sock:
            sender_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sender_sock.sendto(packet_bytes, (self.broadcast_ip, self.port))

    def _assemble_packet(self, msg_header, msg_body):
        self.packet_seq_num += 1
        packet_header = self._build_packet_header_unlocked()
        full_message = {"message_header": msg_header, "message_body": msg_body}
        packet = {"packet_header": packet_header, "messages": [full_message]}
        message_str = json.dumps(packet)
        packet["packet_header"]["packet_length"] = len(message_str)
        packet["messages"][0]["message_header"]["msg_size"] = len(json.dumps(msg_body))
        return packet

    def _hello_sender_thread(self):
        while True:
            time.sleep(self.hello_interval)
            with self.table_lock:
                self.hello_message_seq_num += 1
                self.control_traffic_counts['HELLO'] += 1
                body = self._build_hello_body_unlocked()
                header = self._build_message_header_unlocked("HELLO", self.neighbor_hold_time, 1, 0, self.hello_message_seq_num)
                packet = self._assemble_packet(header, body)
            self._broadcast(json.dumps(packet).encode('utf-8'))
            self.general_logger.info("HELLO_SENT")

    def _tc_sender_thread(self):
        while True:
            time.sleep(self.tc_interval)
            with self.table_lock:
                if not self.mpr_selector_set: continue
                self.tc_message_seq_num += 1
                self.control_traffic_counts['TC'] += 1
                current_time = time.time()
                for t_tuple in [t for t in self.topology_table if t[1] == self.my_ip]: del self.topology_table[t_tuple]
                for selector_ip in self.mpr_selector_set: self.topology_table[(selector_ip, self.my_ip)] = {'seq_num': self.tc_message_seq_num, 'last_updated': current_time}
                body = self._build_tc_body_unlocked()
                header = self._build_message_header_unlocked("TC", self.topology_hold_time, 255, 0, self.tc_message_seq_num)
                packet = self._assemble_packet(header, body)
            self._broadcast(json.dumps(packet).encode('utf-8'))
            self.general_logger.info(f"TC_SENT,seq={self.tc_message_seq_num}")

    def _hna_sender_thread(self):
        while True:
            time.sleep(self.hna_interval)
            with self.table_lock:
                self.hna_message_seq_num += 1
                self.control_traffic_counts['HNA'] += 1
                body = self._build_hna_body_unlocked()
                header = self._build_message_header_unlocked("HNA", self.hna_hold_time, 255, 0, self.hna_message_seq_num)
                packet = self._assemble_packet(header, body)
            self._broadcast(json.dumps(packet).encode('utf-8'))
            self.general_logger.info("HNA_SENT")

    def _mid_sender_thread(self):
        while True:
            time.sleep(self.mid_interval)
            with self.table_lock:
                self.mid_message_seq_num += 1
                self.control_traffic_counts['MID'] += 1
                body = self._build_mid_body_unlocked()
                header = self._build_message_header_unlocked("MID", self.mid_hold_time, 255, 0, self.mid_message_seq_num)
                packet = self._assemble_packet(header, body)
            self._broadcast(json.dumps(packet).encode('utf-8'))
            self.general_logger.info("MID_SENT")

    # The rest of the functions (builders, receivers, processing, cleanup, etc.) are below
    def _build_hello_body_unlocked(self): return {"htime": self.hello_interval, "willingness": self.willingness, "links": [{"link_code": "HEARD", "neighbor_ip": ip} for ip in self.neighbor_table.keys()], "mpr_set": list(self.mpr_set)}
    def _build_tc_body_unlocked(self): return {"mpr_selectors": list(self.mpr_selector_set)}
    def _build_hna_body_unlocked(self): return {"networks": self.hna_networks}
    def _build_mid_body_unlocked(self): return {"virtual_interfaces": self.virtual_interfaces}
    def _build_message_header_unlocked(self, msg_type, vtime, ttl, hop_count, seq_num): return {"msg_type": msg_type, "vtime": vtime, "msg_size": 0, "originator_address": self.my_ip, "ttl": ttl, "hop_count": hop_count, "msg_seq_num": seq_num}
    def _build_packet_header_unlocked(self): return {"packet_length": 0, "packet_seq_num": self.packet_seq_num}
    
    def _receiver_thread(self):
        receiver_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        receiver_sock.bind(('0.0.0.0', self.port))
        while True:
            try:
                data, addr = receiver_sock.recvfrom(65535)
                sender_ip = addr[0]

                # Attempt to decode as JSON. If it fails, it's not a valid packet for us.
                packet = json.loads(data.decode('utf-8'))

                # 1. Check if it's an EXTERNAL COMMAND from the test_runner.py script.
                # These commands do not originate from an OLSR node and should be processed immediately.
                if packet.get("type") == "COMMAND":
                    self._process_command_message(packet)
                    continue # Command processed, wait for the next packet.

                # 2. If not a command, it must be an OLSR packet. Apply isolation rules.
                # The sender_ip is the IP of the node that sent the packet to us.
                if sender_ip in self.my_blacklist:
                    continue # Ignore packets from blacklisted neighbors.

                # 3. Process the OLSR messages within the packet.
                # The originator_address inside the message might be different from the sender_ip.
                for message in packet.get("messages", []):
                    header = message.get("message_header", {})
                    body = message.get("message_body", {})
                    originator_ip = header.get("originator_address")

                    # Ignore our own broadcasted messages.
                    if not originator_ip or originator_ip == self.my_ip:
                        continue
                        
                    msg_type = header.get("msg_type")
                    if msg_type == "HELLO":
                        self._process_hello_message(header, body)
                    elif msg_type == "TC":
                        self._process_tc_message(header, body, sender_ip)
                    elif msg_type == "HNA":
                        self._process_hna_message(header, body, sender_ip)
                    elif msg_type == "MID":
                        self._process_mid_message(header, body, sender_ip)
                    elif msg_type == "DATA":
                        # This single function handles receiving, forwarding, PDR, and Throughput
                        self._process_data_message(header, body)

            except (json.JSONDecodeError, KeyError, TypeError):
                # This can happen with malformed packets. Silently ignore.
                # self.general_logger.warning(f"Malformed or non-JSON packet received from {addr[0]}")
                pass
            except Exception as e:
                self.general_logger.error(f"RECEIVER_THREAD_CRITICAL_ERROR,error={e}")
                print(f"An error occurred in receiver_thread: {e}")


    
    def _process_command_message(self, command):
        params = command.get("params", {})
        dest = params.get("destination")
        count = params.get("count")
        file_name = params.get("file_name") # New: for throughput test
        
        if command.get("command") == "START_PDR_TEST" and dest and count:
            print(f"Received command to send {count} packets to {dest}")
            threading.Thread(target=self._send_data_task, args=(dest, count)).start()
        elif command.get("command") == "START_THROUGHPUT_TEST" and dest and file_name:
            print(f"Received command to send file '{file_name}' to {dest}")
            threading.Thread(target=self._send_file_task, args=(dest, file_name)).start()

    def _send_data_task(self, destination, count):
        # This is for PDR test
        for i in range(count):
            self._send_data_packet(destination, f"Test packet {i+1}", i + 1)
            time.sleep(0.5) # Small delay between packets for PDR

    def _send_data_packet(self, final_destination, payload, packet_id):
        # This sends a single PDR test packet
        with self.table_lock:
            route_info = self.routing_table.get(final_destination)
            if not route_info:
                self.general_logger.warning(f"NO_ROUTE_TO_DESTINATION_PDR,dest={final_destination},packet_id={packet_id}")
                print(f"No route to {final_destination}, dropping packet {packet_id}"); return
            next_hop = route_info['next_hop']; 
            
            data_body = {
                "final_destination": final_destination, 
                "payload": payload, 
                "packet_id": packet_id, 
                "creation_timestamp": time.time(), # This is for PDR delay
                "path_taken": [self.my_ip],
                "is_pdr_test": True # Added flag
            }
            msg_header = self._build_message_header_unlocked("DATA", 0, 255, 0, packet_id)
            packet = self._assemble_packet(msg_header, data_body)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
              sock.sendto(json.dumps(packet).encode('utf-8'), (next_hop, self.port))

            self.data_traffic_counts['DATA_SENT'] += 1
    
            # <<< PDR SENT Logging format >>>
            self.data_logger.info(f"SENT,PDR,{packet_id},{time.time()},{self.my_ip},{final_destination},,,") # Empty fields for Delay, Path, FileSizeMB, ThroughputMbps

    # New function: Send a file for Throughput test
    def _send_file_task(self, final_destination, file_name):
        # --- FIX: Handle numeric file_name by creating a dummy file ---
        if file_name.isdigit():
            dummy_file_name = f"dummy_{file_name}MB.bin"
            file_size_mb = int(file_name)
            file_size_bytes = file_size_mb * 1024 * 1024
            
            # Create a dummy file if it doesn't exist or size is wrong
            if not os.path.exists(dummy_file_name) or os.path.getsize(dummy_file_name) != file_size_bytes:
                print(f"Creating a dummy file '{dummy_file_name}' of {file_size_mb} MB...")
                self.general_logger.info(f"CREATING_DUMMY_FILE,name={dummy_file_name},size_mb={file_size_mb}")
                with open(dummy_file_name, 'wb') as f:
                    f.write(os.urandom(file_size_bytes))
            
            file_to_send = dummy_file_name
        else:
            file_to_send = file_name

        try:
            with open(file_to_send, 'rb') as f:
                file_data = f.read()
            
            file_size_bytes = len(file_data)
            chunk_size = 1024 # You can change this
            total_chunks = (file_size_bytes + chunk_size - 1) // chunk_size

            with self.table_lock:
                self.file_transfer_counter += 1
                current_file_id = f"FILE_{self.file_transfer_counter}_{self.my_ip.replace('.', '-')}"

            self.general_logger.info(f"THROUGHPUT_TEST_STARTED,file_id={current_file_id},source={self.my_ip},dest={final_destination},file_name={file_to_send},size_bytes={file_size_bytes}")
            start_transfer_time = time.time()
            
            for i in range(total_chunks):
                start_index = i * chunk_size
                end_index = min((i + 1) * chunk_size, file_size_bytes)
                payload_chunk = file_data[start_index:end_index]
                
                self._send_data_packet_for_file(
                    final_destination, 
                    payload_chunk.decode('latin1'), 
                    i + 1, # packet_id (chunk_id)
                    current_file_id, 
                    total_chunks, 
                    start_transfer_time,
                    file_size_bytes
                )
                time.sleep(0.001) 
            
            self.general_logger.info(f"THROUGHPUT_TEST_FILE_SEND_INITIATED,file_id={current_file_id},total_chunks={total_chunks}")

        except FileNotFoundError:
            self.general_logger.error(f"FILE_NOT_FOUND,{file_to_send},on={self.my_ip}")
            print(f"Error: File '{file_to_send}' not found on {self.my_ip}")
        except Exception as e:
            self.general_logger.error(f"ERROR_SENDING_FILE,{file_to_send},error={e}")
            print(f"An error occurred while sending file '{file_to_send}': {e}")



    def _send_data_packet_for_file(self, final_destination, payload, chunk_id, file_id, total_chunks, file_creation_timestamp, file_size_bytes):
        # This sends a single chunk of a file
        with self.table_lock:
            route_info = self.routing_table.get(final_destination)
            if not route_info:
                self.general_logger.warning(f"NO_ROUTE_TO_DESTINATION_CHUNK,dest={final_destination},file_id={file_id},chunk_id={chunk_id}")
                return

            next_hop = route_info['next_hop']
            
            data_body = {
                "final_destination": final_destination,
                "payload": payload,
                "packet_id": chunk_id,          # Chunk ID for this file
                "file_id": file_id,             # Unique ID for the entire file transfer
                "total_chunks": total_chunks,   # Total chunks in the file
                "file_creation_timestamp": file_creation_timestamp, # Timestamp when first chunk was sent
                "chunk_creation_timestamp": time.time(), # Timestamp when this specific chunk was created
                "path_taken": [self.my_ip],
                "is_pdr_test": False,           # Flag to distinguish from PDR test packets
                "actual_file_size_bytes": file_size_bytes # Actual file size for calculation at dest
            }
            # Use self.packet_seq_num for overall packet sequencing, or a separate one for data packets
            msg_header = self._build_message_header_unlocked("DATA", 0, 255, 0, self.packet_seq_num + 1)
            packet = self._assemble_packet(msg_header, data_body)

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(json.dumps(packet).encode('utf-8'), (next_hop, self.port))
            
            self.data_traffic_counts['DATA_SENT'] += 1
            # Logging for individual chunks if needed, or focus on end-to-end file transfer
            # self.data_logger.info(f"SENT_CHUNK,{file_id},{chunk_id},{time.time()},{self.my_ip},{final_destination},,")

    def _process_data_message(self, header, body):
        with self.table_lock:
            final_destination = body.get("final_destination")
            packet_id = body.get("packet_id") # For PDR it's packet ID, for Throughput it's chunk ID
            path = body.get("path_taken", [])

            # Simple loop detection
            if self.my_ip in path:
                # Differentiate based on file_id presence
                log_prefix = f"LOOP_DETECTED,FileID={body.get('file_id', 'N/A')}," if body.get('file_id') else "LOOP_DETECTED,"
                self.general_logger.warning(f"{log_prefix}packet_id={packet_id},path={path}. Dropping.")
                return

            path.append(self.my_ip)

            if final_destination == self.my_ip:
                # Packet has reached its destination
                self.data_traffic_counts['DATA_RECEIVED'] += 1
                path_str = "->".join(path)

                is_pdr_test = body.get("is_pdr_test", False)
                
                if is_pdr_test:
                    # Process as a PDR test packet
                    creation_time = body.get("creation_timestamp", 0)
                    delay = time.time() - creation_time
                    
                    # Log PDR RECEIVED (FileID is 'PDR', other throughput fields are empty)
                    self.data_logger.info(f"RECEIVED,PDR,{packet_id},{time.time()},{header['originator_address']},{self.my_ip},{delay:.4f},{path_str},,")
                    print(f"✅ Received DATA packet {packet_id} from {header['originator_address']}. Delay: {delay:.4f}s. Path: {path_str}")
                else:
                    # Process as a Throughput file chunk
                    file_id = body.get("file_id")
                    chunk_id = packet_id # For clarity
                    total_chunks = body.get("total_chunks")
                    file_creation_timestamp = body.get("file_creation_timestamp")
                    chunk_creation_timestamp = body.get("chunk_creation_timestamp", 0)
                    actual_file_size_bytes = body.get("actual_file_size_bytes", 0)
                    
                    # Delay for this individual chunk
                    chunk_delay = time.time() - chunk_creation_timestamp
                    
                    # Log individual chunk received
                    self.data_logger.info(f"RECEIVED_CHUNK,{file_id},{chunk_id},{time.time()},{header['originator_address']},{self.my_ip},{chunk_delay:.4f},{path_str},,")
                    
                    if file_id:
                        if file_id not in self.receiving_files:
                            self.receiving_files[file_id] = {
                                'received_chunks': {},
                                'total_chunks': total_chunks,
                                'start_time': file_creation_timestamp,
                                'file_size_bytes': actual_file_size_bytes, # Use actual file size sent by source
                                'current_path': path # Store path for the file completion log
                            }
                        
                        self.receiving_files[file_id]['received_chunks'][chunk_id] = True # Mark chunk as received
                        
                        # If all chunks for this file_id have been received
                        if len(self.receiving_files[file_id]['received_chunks']) == total_chunks:
                            end_transfer_time = time.time()
                            total_transfer_duration = end_transfer_time - self.receiving_files[file_id]['start_time']
                            
                            if total_transfer_duration > 0:
                                file_size_mb_received = self.receiving_files[file_id]['file_size_bytes'] / (1024 * 1024)
                                throughput_mbps = (self.receiving_files[file_id]['file_size_bytes'] * 8) / (total_transfer_duration * 1024 * 1024) # bits per second
                                
                                # Log THROUGHPUT event
                                self.data_logger.info(f"THROUGHPUT,{file_id},{total_chunks},{end_transfer_time},{header['originator_address']},{self.my_ip},{total_transfer_duration:.4f},{'->'.join(self.receiving_files[file_id]['current_path'])},{file_size_mb_received:.2f},{throughput_mbps:.2f}")
                                self.general_logger.info(f"FILE_TRANSFER_COMPLETE,file_id={file_id},throughput={throughput_mbps:.2f}Mbps,duration={total_transfer_duration:.4f}s")
                                print(f"✅ Received FILE {file_id} from {header['originator_address']}. Throughput: {throughput_mbps:.2f} Mbps. Total time: {total_transfer_duration:.4f}s.")
                            else:
                                self.general_logger.warning(f"THROUGHPUT_ZERO_DURATION,file_id={file_id}")
                                print(f"Warning: File {file_id} transfer duration was zero or negative.")
                            
                            del self.receiving_files[file_id] # Clean up
                    else:
                        self.general_logger.warning(f"RECEIVED_CHUNK_NO_FILE_ID,packet_id={chunk_id}")

            else:
                # We need to forward this packet.
                route_info = self.routing_table.get(final_destination)
                if route_info:
                    next_hop = route_info['next_hop']
                    
                    # --- START: CRITICAL FIX FOR FORWARDING ---
                    
                    # 1. Modify the header and body for forwarding.
                    header['hop_count'] += 1
                    header['ttl'] -= 1 # Decrement TTL
                    body['path_taken'] = path # Update the path taken list

                    # 2. Re-construct the packet structure WITHOUT calling _assemble_packet.
                    # _assemble_packet is for creating NEW packets, not for forwarding existing ones.
                    # The structure must match what the receiver expects: a main dict with a 'messages' list.
                    forward_packet = {
                        # The packet_header is not strictly needed for forwarding if we rebuild,
                        # but we can create a minimal one. Let's keep the original packet's structure.
                        "packet_header": {
                            "packet_length": 0, # This will be recalculated by len() later
                            "packet_seq_num": self.packet_seq_num # Use current node's seq_num
                        },
                        "messages": [
                            {
                                "message_header": header,
                                "message_body": body
                            }
                        ]
                    }

                    # 3. Convert the corrected packet structure to bytes.
                    forward_bytes = json.dumps(forward_packet).encode('utf-8')

                    # 4. Update the packet length in the header (optional but good practice).
                    # Note: This part is complex to get right without re-encoding.
                    # For now, the receiver doesn't use packet_length, so we can omit updating it.
                    # The important part is that the JSON structure is correct.

                    # 5. Send the bytes.
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.sendto(forward_bytes, (next_hop, self.port))
                    
                    # --- END: CRITICAL FIX FOR FORWARDING ---

                    self.data_traffic_counts['DATA_FORWARDED'] += 1
                    # Add a log entry to confirm forwarding happened
                    log_prefix = f"FORWARDED_CHUNK,FileID={body.get('file_id', 'N/A')}," if not body.get("is_pdr_test") else "FORWARDED_PDR,"
                    self.general_logger.info(f"{log_prefix}packet_id={packet_id},from={path[-2]},to={next_hop},final_dest={final_destination}")

                else:
                    log_prefix = f"NO_ROUTE_TO_FORWARD,FileID={body.get('file_id', 'N/A')}," if not body.get("is_pdr_test") else "NO_ROUTE_TO_FORWARD_PDR,"
                    self.general_logger.warning(f"{log_prefix}dest={final_destination},packet_id={packet_id}. Dropping.")
                    print(f"No route to {final_destination}, dropping DATA packet {packet_id}")


    def _process_hello_message(self, header, body):
        with self.table_lock:
            originator_ip = header['originator_address']
            self.general_logger.info(f"HELLO_RECEIVED,from={originator_ip}")
            advertised_ips = {link.get('neighbor_ip') for link in body.get('links', [])}
            link_status = 'SYM' if self.my_ip in advertised_ips else 'ASYM'
            self.neighbor_table[originator_ip] = {'status': link_status, 'last_heard': time.time()}
            if not self._neighbor_discovery_complete:
                sym_neighbors = {ip for ip, data in self.neighbor_table.items() if data['status'] == 'SYM'}
                if len(sym_neighbors) >= self.expected_sym_neighbors:
                    self.general_logger.info("NEIGHBOR_DISCOVERY_COMPLETE")
                    self._neighbor_discovery_complete = True
            advertised_mpr_set = set(body.get('mpr_set', []))
            if link_status == 'SYM' and self.my_ip in advertised_mpr_set: self.mpr_selector_set.add(originator_ip)
            else: self.mpr_selector_set.discard(originator_ip)
            for candidate_ip in advertised_ips:
                if candidate_ip and candidate_ip != self.my_ip and candidate_ip not in self.neighbor_table:
                    # In OLSR, two-hop entries are specifically for neighbors of a symmetric neighbor
                    # and are NOT directly reachable from self.
                    # This simplified logic treats any non-1-hop neighbor as 2-hop via the originator.
                    # A more robust OLSR implementation would track 2-hop neighbors via each symmetric neighbor explicitly.
                    self.two_hop_table[candidate_ip] = {'via_neighbor': originator_ip, 'last_updated': time.time()}
            self._pretty_print_tables(f"Tables updated after HELLO from {originator_ip}")
    
    def _process_tc_message(self, header, body, sender_ip):
        with self.table_lock:
            originator = header['originator_address']
            seq_num = header['msg_seq_num']
            self.general_logger.info(f"TC_RECEIVED,originator={originator},seq={seq_num},from={sender_ip}")

            if self.last_tc_seq_nums.get(originator, -1) >= seq_num:
                self.general_logger.info(f"TC_DUPLICATE_OR_OLD,originator={originator},seq={seq_num}. Ignoring.")
                return # Ignore old or duplicate TC message

            self.last_tc_seq_nums[originator] = seq_num
            current_time = time.time()

            # Update topology table based on the new TC message
            # First, remove old entries from this originator
            tuples_to_remove = [t for t in self.topology_table if t[1] == originator]
            for t_tuple in tuples_to_remove:
                del self.topology_table[t_tuple]
            
            # Then, add new entries
            for selector_ip in body.get("mpr_selectors", []):
                self.topology_table[(selector_ip, originator)] = {'seq_num': seq_num, 'last_updated': current_time}
            
            self.general_logger.info(f"TOPOLOGY_TABLE_UPDATED,originator={originator}")
            # self._pretty_print_tables(f"Tables updated after TC from {originator}") # Uncomment for intense debugging

            # --- START: CRITICAL FIX FOR TC FORWARDING ---
            # Forward TC message if TTL > 1 and this node was selected as an MPR by the sender.
            if header['ttl'] > 1 and sender_ip in self.mpr_selector_set:
                # 1. Decrement TTL for the forwarded packet.
                header['ttl'] -= 1
                
                # 2. Re-construct the packet structure correctly for forwarding.
                # DO NOT use _assemble_packet, as it creates a new packet wrapper.
                forward_packet = {
                    "packet_header": { "packet_seq_num": self.packet_seq_num },
                    "messages": [{ "message_header": header, "message_body": body }]
                }
                
                # 3. Broadcast the forwarded TC message.
                self._broadcast(json.dumps(forward_packet).encode('utf-8'))
                self.general_logger.info(f"TC_FORWARDED,originator={originator},seq={seq_num},from={sender_ip}")
            # --- END: CRITICAL FIX FOR TC FORWARDING ---

    
    def _process_hna_message(self, header, body, sender_ip):
        with self.table_lock:
            originator = header['originator_address']; seq_num = header['msg_seq_num']
            if self.last_hna_seq_nums.get(originator, -1) >= seq_num: return
            self.last_hna_seq_nums[originator] = seq_num
            for network in body.get("networks", []): self.hna_table[network] = {'gateway': originator, 'last_updated': time.time()}
            self._pretty_print_tables(f"Tables updated after HNA from {originator}")
            if header['ttl'] > 1 and sender_ip in self.mpr_selector_set:
                header['ttl'] -= 1; forward_packet = self._assemble_packet(header, body)
                self._broadcast(json.dumps(forward_packet).encode('utf-8'))
    
    def _process_mid_message(self, header, body, sender_ip):
        with self.table_lock:
            originator = header['originator_address']; seq_num = header['msg_seq_num']
            if self.last_mid_seq_nums.get(originator, -1) >= seq_num: return
            self.last_mid_seq_nums[originator] = seq_num
            current_time = time.time()
            for interface in body.get("virtual_interfaces", []): self.interface_association_table[interface] = {'main_addr': originator, 'last_updated': current_time}
            self._pretty_print_tables(f"Tables updated after MID from {originator}")
            if header['ttl'] > 1 and sender_ip in self.mpr_selector_set:
                header['ttl'] -= 1; forward_packet = self._assemble_packet(header, body)
                self._broadcast(json.dumps(forward_packet).encode('utf-8'))
    
    def _routing_table_thread(self):
        # Give some time for initial neighbor/topology discovery before calculating routes
        time.sleep(self.tc_interval + 0.5) 
        while True:
            with self.table_lock:
                self._calculate_routing_table()
                self.general_logger.info("ROUTING_TABLE_RECALCULATED")
                self._pretty_print_tables("Routing Table Recalculated")
            time.sleep(self.routing_table_interval)
    def _calculate_routing_table(self):
        with self.table_lock:
            new_routing_table = {}
            
            # 1. Build the graph from neighbor and topology tables
            graph = {}
            all_nodes = {self.my_ip}
            
            # Add all known nodes to the graph to avoid KeyErrors
            for ip in self.neighbor_table: all_nodes.add(ip)
            for (dest, last) in self.topology_table:
                all_nodes.add(dest)
                all_nodes.add(last)

            for node in all_nodes:
                graph[node] = set()

            # Add symmetric 1-hop neighbors as bidirectional links
            for neighbor, data in self.neighbor_table.items():
                if data['status'] == 'SYM':
                    graph[self.my_ip].add(neighbor)
                    if neighbor in graph:
                        graph[neighbor].add(self.my_ip)

            # Add topology links (from originator 'last' to its MPR selector 'dest')
            for (dest, last) in self.topology_table.keys():
                # Ensure both nodes are in the graph before adding edge
                if last in graph and dest in graph:
                    graph[last].add(dest)

            # 2. Run Dijkstra's Algorithm
            distances = {node: float('infinity') for node in all_nodes}
            previous_nodes = {node: None for node in all_nodes}
            distances[self.my_ip] = 0
            pq = [(0, self.my_ip)]

            while pq:
                dist, current_node = heapq.heappop(pq)

                if dist > distances[current_node]:
                    continue

                for neighbor in graph.get(current_node, set()):
                    if distances[current_node] + 1 < distances[neighbor]:
                        distances[neighbor] = distances[current_node] + 1
                        previous_nodes[neighbor] = current_node
                        heapq.heappush(pq, (distances[neighbor], neighbor))

            # --- START: CRITICAL FIX FOR NEXT HOP CALCULATION ---
            
            # 3. Build the routing table by tracing back the path
            for dest_node, dist in distances.items():
                if dest_node == self.my_ip or dist == float('infinity'):
                    continue
                
                # Start tracing back from the destination
                path_tracer = dest_node
                
                # Keep moving backwards until the node BEFORE the current one is ourself (my_ip)
                # This finds the first hop on the path from my_ip to dest_node
                while previous_nodes.get(path_tracer) and previous_nodes.get(path_tracer) != self.my_ip:
                    path_tracer = previous_nodes.get(path_tracer)
                
                # `path_tracer` is now the correct next hop.
                # If dest_node is a direct neighbor, the while loop condition is false immediately,
                # and path_tracer correctly remains dest_node.
                # If dest_node is 2 hops away (e.g., 1->2->3), the path is 3->2->1.
                #   - path_tracer starts as 3.
                #   - previous_nodes[3] is 2. 2 is not 1. So path_tracer becomes 2.
                #   - previous_nodes[2] is 1. The loop terminates.
                #   - The correct next hop is 2.
                next_hop_node = path_tracer
                new_routing_table[dest_node] = {'next_hop': next_hop_node, 'distance': int(dist)}

            # --- END: CRITICAL FIX ---

            # 4. Add HNA and MID routes based on the calculated routing table
            for network, data in self.hna_table.items():
                gateway_ip = data['gateway']
                if gateway_ip in new_routing_table:
                    route_to_gateway = new_routing_table[gateway_ip]
                    new_routing_table[network] = {'next_hop': route_to_gateway['next_hop'], 'distance': route_to_gateway['distance'] + 1}
                elif gateway_ip in self.neighbor_table and self.neighbor_table[gateway_ip]['status'] == 'SYM':
                    new_routing_table[network] = {'next_hop': gateway_ip, 'distance': 2}

            for virtual_if, data in self.interface_association_table.items():
                main_addr = data['main_addr']
                if main_addr in new_routing_table:
                    route_to_main = new_routing_table[main_addr]
                    new_routing_table[virtual_if] = {'next_hop': route_to_main['next_hop'], 'distance': route_to_main['distance'] + 1}
                elif main_addr in self.neighbor_table and self.neighbor_table[main_addr]['status'] == 'SYM':
                    new_routing_table[virtual_if] = {'next_hop': main_addr, 'distance': 2}

            self.routing_table = new_routing_table

    def _cleanup_thread(self):
        while True:
            time.sleep(self.hello_interval) # Run cleanup periodically
            with self.table_lock:
                current_time = time.time()
                
                # Neighbors (1-hop)
                neighbors_to_remove = [ip for ip, data in self.neighbor_table.items() if current_time - data['last_heard'] > self.neighbor_hold_time]
                for ip in neighbors_to_remove:
                    if ip in self.neighbor_table: del self.neighbor_table[ip]
                    self.mpr_selector_set.discard(ip) # Remove from MPR selectors if they were one

                # Two-hop Neighbors
                # Remove if via_neighbor is no longer in neighbor table or expired
                two_hops_to_remove = [
                    ip for ip, data in list(self.two_hop_table.items()) 
                    if data['via_neighbor'] not in self.neighbor_table or 
                       current_time - data['last_updated'] > self.two_hop_hold_time
                ]
                for ip in set(two_hops_to_remove):
                    if ip in self.two_hop_table: del self.two_hop_table[ip]

                # Topology Table (Links)
                tuples_to_remove = [t_tuple for t_tuple, data in self.topology_table.items() if current_time - data['last_updated'] > self.topology_hold_time]
                for t_tuple in tuples_to_remove:
                    if t_tuple in self.topology_table: del self.topology_table[t_tuple]
                    # No need to remove from last_tc_seq_nums immediately, it's used for deduplication
                    # self.last_tc_seq_nums.pop(t_tuple[1], None) 

                # HNA Table
                hna_to_remove = [net for net, data in self.hna_table.items() if current_time - data['last_updated'] > self.hna_hold_time]
                for net in hna_to_remove:
                    if net in self.hna_table: del self.hna_table[net]

                # Interface Association Table (MID)
                mid_to_remove = [ip for ip, data in self.interface_association_table.items() if current_time - data['last_updated'] > self.mid_hold_time]
                for ip in mid_to_remove:
                    if ip in self.interface_association_table: del self.interface_association_table[ip]

                if neighbors_to_remove or two_hops_to_remove or tuples_to_remove or hna_to_remove or mid_to_remove:
                    self.general_logger.info("CLEANUP_EVENT")
                    self._pretty_print_tables(f"🧹 Cleanup Event")
    
    def _pretty_print_tables(self, header="Current Tables"):
        print(f"\n--- {header} (Node {self.my_ip}) ---")
        current_time = time.time()
        print("My MPR Set:", sorted(list(self.mpr_set)) if self.mpr_set else "(empty)")
        print("My MPR Selectors:", sorted(list(self.mpr_selector_set)) if self.mpr_selector_set else "(empty)")
        print("HNA Table (Gateways):")
        if not self.hna_table: print("  (empty)")
        else:
            for net, data in self.hna_table.items(): print(f"  - Network: {net:<15} | via Gateway: {data['gateway']:<15}")
        print("Interface Association Table (MID):")
        if not self.interface_association_table: print("  (empty)")
        else:
            for interface, data in sorted(self.interface_association_table.items()):
                age = current_time - data['last_updated']; print(f"  - Interface: {interface:<15} | Main Addr: {data['main_addr']:<15} ({age:.1f}s ago)")
        print("Neighbor Table (1-hop):")
        if not self.neighbor_table: print("  (empty)")
        else:
            for ip, data in self.neighbor_table.items():
                age = current_time - data['last_heard']; print(f"  - {ip:<15} | Status: {data['status']:<4} | Last Heard: {datetime.fromtimestamp(data['last_heard']).strftime('%H:%M:%S')} ({age:.1f}s ago)")
        print("2-Hop Neighbors Table:")
        if not self.two_hop_table: print("  (empty)")
        else:
            for ip, data in self.two_hop_table.items():
                age = current_time - data['last_updated']; via = data['via_neighbor']; print(f"  - {ip:<15} | via: {via:<15} | Last Updated: {datetime.fromtimestamp(data['last_updated']).strftime('%H:%M:%S')} ({age:.1f}s ago)")
        print("Topology Table (Links):")
        if not self.topology_table: print("  (empty)")
        else:
            for (dest, last), data in sorted(self.topology_table.items()):
                age = current_time - data['last_updated']; print(f"  - (Dest: {dest:<15}, Last: {last:<15}) | Seq: {data['seq_num']} ({age:.1f}s ago)")
        print("Routing Table:")
        if not self.routing_table: print("  (empty)")
        else:
            for dest, data in sorted(self.routing_table.items()): print(f"  - Dest: {dest:<15} | Next Hop: {data['next_hop']:<15} | Hops: {data['distance']}")
        print("Traffic Counts (Control):", self.control_traffic_counts)
        print("Traffic Counts (Data):", self.data_traffic_counts)
        print("---------------------------------------------------\n")
    
    def _mpr_selection_thread(self):
        # Give some time for initial neighbor discovery
        time.sleep(self.hello_interval * 2) 
        while True:
            with self.table_lock: 
                self._calculate_mpr_set()
                self.general_logger.info(f"MPR_SET_RECALCULATED,set={sorted(list(self.mpr_set))}")
                self._pretty_print_tables("MPR Set Recalculated")
            time.sleep(self.mpr_calculation_interval)
    
    def _calculate_mpr_set(self):
        self.mpr_set.clear() # Clear previous MPR set
        
        # S(1) set: Symmetric 1-hop neighbors
        s1_neighbors = {ip for ip, data in self.neighbor_table.items() if data['status'] == 'SYM'}
        
        # D_2 set: Set of 2-hop neighbors that are reachable via symmetric 1-hop neighbors
        uncovered_2_hop_set = {
            ip for ip, data in self.two_hop_table.items() 
            if data['via_neighbor'] in s1_neighbors # Ensure the intermediate neighbor is symmetric
        }
        
        # Add symmetric neighbors that are MPRs for other nodes to the MPR set if willingness is high
        # (Simplified: In a full OLSR, willingness is used more for tie-breaking)

        # Main MPR selection loop
        while uncovered_2_hop_set:
            best_candidate = None
            max_coverage = -1
            
            # Candidates for MPRs are symmetric 1-hop neighbors
            mpr_candidates = s1_neighbors - self.mpr_set # Only consider neighbors not already in MPR set
            
            # Iterate through all possible MPR candidates
            for candidate in mpr_candidates:
                # Find 2-hop neighbors that 'candidate' covers
                reachable_by_candidate = {
                    ip for ip, data in self.two_hop_table.items() 
                    if data['via_neighbor'] == candidate and ip in uncovered_2_hop_set # Only consider uncovered 2-hops
                }
                
                # Check coverage of uncovered 2-hop neighbors
                coverage_count = len(reachable_by_candidate)
                
                # Select the candidate that covers the most *uncovered* 2-hop neighbors
                # Prioritize based on coverage, then willingness (if implemented), then IP address for tie-breaking
                if coverage_count > max_coverage:
                    max_coverage = coverage_count
                    best_candidate = candidate
                elif coverage_count == max_coverage and best_candidate is not None:
                    # Tie-breaking (e.g., choose numerically smallest IP if coverage is equal)
                    if candidate < best_candidate: # Simple IP-based tie-break
                        best_candidate = candidate
            
            if best_candidate is None:
                # No more 2-hop neighbors can be covered, or no candidates left
                break 
            
            # Add the chosen best candidate to the MPR set
            self.mpr_set.add(best_candidate)
            
            # Remove newly covered 2-hop neighbors from the uncovered set
            newly_covered = {
                ip for ip, data in self.two_hop_table.items() 
                if data['via_neighbor'] == best_candidate
            }
            uncovered_2_hop_set -= newly_covered

if __name__ == "__main__":
    # --- 1. CONFIGURE THIS NODE ---
    MY_IP_ADDRESS = '192.168.10.1' # <<< CHANGE THIS FOR EACH RASPBERRY PI >>>
    
    # --- 2. DEFINE THE ENTIRE NETWORK TOPOLOGY AND NODE ROLES ---
    ALL_NODE_IPS = ['192.168.10.1', '192.168.10.2', '192.168.10.3', '192.168.10.4', '192.168.10.5']
    GATEWAY_NODE_IP = '192.168.10.1'
    NODE_WITH_VIRTUAL_INTERFACES = '192.168.10.2'
    VIRTUAL_INTERFACES_LIST = ['10.10.10.2', '10.20.20.2'] # Example virtual interfaces
    HNA_ROUTES_TO_ADVERTISE = ['0.0.0.0/0'] # Advertise default route for gateway

    # --- 3. NODE DETERMINES ITS OWN CONFIGURATION ---
    am_i_gateway = (MY_IP_ADDRESS == GATEWAY_NODE_IP)
    my_virtual_interfaces = VIRTUAL_INTERFACES_LIST if MY_IP_ADDRESS == NODE_WITH_VIRTUAL_INTERFACES else None
    my_hna_routes = HNA_ROUTES_TO_ADVERTISE if am_i_gateway else None
    
    # Calculate expected symmetric neighbors considering isolation rules
    # This assumes all non-blacklisted nodes are potential symmetric neighbors
    # This might need refinement based on actual network conditions/layout.
    expected_neighbors_count = len(ALL_NODE_IPS) - 1 # Total nodes minus self
    # Subtract any IPs that are blacklisted for THIS node (as they won't be symmetric)
    expected_neighbors_count -= len(ISOLATION_RULES.get(MY_IP_ADDRESS, []))
    # Note: This is a rough estimate. Actual symmetric neighbors depend on signal quality, etc.

    # --- 4. CREATE AND START THE NODE ---
    node = OlsrNode(
        my_ip=MY_IP_ADDRESS,
        expected_sym_neighbors=expected_neighbors_count,
        is_gateway=am_i_gateway,
        virtual_interfaces=my_virtual_interfaces,
        hna_networks=my_hna_routes
    )
    node.start()