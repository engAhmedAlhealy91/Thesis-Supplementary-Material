# network.py
# Contains the OlsrNode class, representing our virtual Network Layer.

import socket
import time
import threading
import json
from datetime import datetime
import heapq

ISOLATION_RULES = {
    '192.168.10.1': ['192.168.10.3','192.168.10.4' ,'192.168.10.5'],
    '192.168.10.2': ['192.168.10.5'],
    '192.168.10.3': ['192.168.10.1'],
    '192.168.10.4': ['192.168.10.1', '192.168.10.5'],
    '192.168.10.5': ['192.168.10.1', '192.168.10.2','192.168.10.4']
}

class OlsrNode:
    def __init__(self, my_ip, olsr_port=8698, broadcast_ip='192.168.10.255'):
        self.my_ip = my_ip
        self.port = olsr_port
        self.broadcast_ip = broadcast_ip
        self.my_blacklist = ISOLATION_RULES.get(my_ip, [])
        # Timers
        self.hello_interval = 2.0
        self.tc_interval = 5.0
        self.routing_table_interval = 5.0
        self.neighbor_hold_time = self.hello_interval * 3
        self.topology_hold_time = self.tc_interval * 3
        self.two_hop_hold_time = self.neighbor_hold_time * 2
        self.mpr_calculation_interval = 5.0
        # Config & Sequence Numbers
        self.willingness = 3
        self.packet_seq_num = 0
        self.hello_message_seq_num = 0
        self.tc_message_seq_num = 0
        # Data Structures
        self.table_lock = threading.RLock()
        self.neighbor_table = {}
        self.two_hop_table = {}
        self.mpr_set = set()
        self.mpr_selector_set = set()
        self.topology_table = {}
        self.routing_table = {}
        self.last_tc_seq_nums = {}
        self.data_callback = None
        print(f"[{self.my_ip}] Network Layer (OLSR Node) initialized.")

    def set_data_callback(self, callback):
        self.data_callback = callback

    def start(self):
        threads = [
            threading.Thread(target=self._hello_sender_thread, daemon=True, name="HelloSender"),
            threading.Thread(target=self._tc_sender_thread, daemon=True, name="TCSender"),
            threading.Thread(target=self._receiver_thread, daemon=True, name="Receiver"),
            threading.Thread(target=self._mpr_selection_thread, daemon=True, name="MPRSelector"),
            threading.Thread(target=self._routing_table_thread, daemon=True, name="RoutingCalculator"),
            threading.Thread(target=self._cleanup_thread, daemon=True, name="Cleanup")
        ]
        for t in threads: t.start()
        print(f"[{self.my_ip}] All OLSR threads started.")

    def send(self, final_destination, payload):
        with self.table_lock:
            route_info = self.routing_table.get(final_destination)
            if not route_info:
                print(f"[Network Layer] No route to {final_destination}, dropping packet.")
                return False
            next_hop = route_info['next_hop']
            data_body = {"final_destination": final_destination, "payload": payload}
            msg_header = self._build_message_header_unlocked("DATA", 0, 255, 0, 0)
            packet = self._assemble_packet(msg_header, data_body)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(json.dumps(packet).encode('utf-8'), (next_hop, self.port))
            return True

    def _process_data_message(self, header, body):
        with self.table_lock:
            final_destination = body.get("final_destination")
            payload = body.get("payload")
            if final_destination == self.my_ip:
                if self.data_callback:
                    self.data_callback(header.get("originator_address"), payload)
            else:
                route_info = self.routing_table.get(final_destination)
                if route_info:
                    next_hop = route_info['next_hop']
                    header['hop_count'] += 1
                    packet = self._assemble_packet(header, body)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.sendto(json.dumps(packet).encode('utf-8'), (next_hop, self.port))
    
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
    
    # ... The rest of the OLSR methods are unchanged ...
    def _hello_sender_thread(self):
        while True:
            time.sleep(self.hello_interval)
            with self.table_lock:
                self.hello_message_seq_num += 1
                body = self._build_hello_body_unlocked()
                header = self._build_message_header_unlocked("HELLO", self.neighbor_hold_time, 1, 0, self.hello_message_seq_num)
                packet = self._assemble_packet(header, body)
            self._broadcast(json.dumps(packet).encode('utf-8'))
    def _tc_sender_thread(self):
        while True:
            time.sleep(self.tc_interval)
            with self.table_lock:
                if not self.mpr_selector_set: continue
                self.tc_message_seq_num += 1
                current_time = time.time()
                for t_tuple in [t for t in self.topology_table if t[1] == self.my_ip]: del self.topology_table[t_tuple]
                for selector_ip in self.mpr_selector_set: self.topology_table[(selector_ip, self.my_ip)] = {'seq_num': self.tc_message_seq_num, 'last_updated': current_time}
                body = self._build_tc_body_unlocked()
                header = self._build_message_header_unlocked("TC", self.topology_hold_time, 255, 0, self.tc_message_seq_num)
                packet = self._assemble_packet(header, body)
            self._broadcast(json.dumps(packet).encode('utf-8'))
    def _build_hello_body_unlocked(self): return {"htime": self.hello_interval, "willingness": self.willingness, "links": [{"link_code": "HEARD", "neighbor_ip": ip} for ip in self.neighbor_table.keys()], "mpr_set": list(self.mpr_set)}
    def _build_tc_body_unlocked(self): return {"mpr_selectors": list(self.mpr_selector_set)}
    def _build_message_header_unlocked(self, msg_type, vtime, ttl, hop_count, seq_num): return {"msg_type": msg_type, "vtime": vtime, "msg_size": 0, "originator_address": self.my_ip, "ttl": ttl, "hop_count": hop_count, "msg_seq_num": seq_num}
    def _build_packet_header_unlocked(self): return {"packet_length": 0, "packet_seq_num": self.packet_seq_num}
    def _receiver_thread(self):
        receiver_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        receiver_sock.bind(('0.0.0.0', self.port))
        while True:
            try:
                data, addr = receiver_sock.recvfrom(2048)
                sender_ip = addr[0]
                if sender_ip in self.my_blacklist: continue
                packet = json.loads(data.decode('utf-8'))
                for message in packet.get("messages", []):
                    header = message.get("message_header", {})
                    body = message.get("message_body", {})
                    originator_ip = header.get("originator_address")
                    if not originator_ip or originator_ip == self.my_ip: continue
                    msg_type = header.get("msg_type")
                    if msg_type == "HELLO": self._process_hello_message(header, body)
                    elif msg_type == "TC": self._process_tc_message(header, body, sender_ip)
                    elif msg_type == "DATA": self._process_data_message(header, body)
            except (json.JSONDecodeError, KeyError, TypeError): pass
            except Exception as e: print(f"An error occurred in receiver_thread: {e}")
    def _process_hello_message(self, header, body):
        with self.table_lock:
            originator_ip = header['originator_address']
            advertised_ips = {link.get('neighbor_ip') for link in body.get('links', [])}
            link_status = 'SYM' if self.my_ip in advertised_ips else 'ASYM'
            self.neighbor_table[originator_ip] = {'status': link_status, 'last_heard': time.time()}
            advertised_mpr_set = set(body.get('mpr_set', []))
            if link_status == 'SYM' and self.my_ip in advertised_mpr_set: self.mpr_selector_set.add(originator_ip)
            else: self.mpr_selector_set.discard(originator_ip)
            for candidate_ip in advertised_ips:
                if candidate_ip and candidate_ip != self.my_ip and candidate_ip not in self.neighbor_table:
                    self.two_hop_table[candidate_ip] = {'via_neighbor': originator_ip, 'last_updated': time.time()}
    def _process_tc_message(self, header, body, sender_ip):
        with self.table_lock:
            originator = header['originator_address']; seq_num = header['msg_seq_num']
            if self.last_tc_seq_nums.get(originator, -1) >= seq_num: return
            self.last_tc_seq_nums[originator] = seq_num
            current_time = time.time()
            for t_tuple in [t for t in self.topology_table if t[1] == originator]: del self.topology_table[t_tuple]
            for selector_ip in body.get("mpr_selectors", []): self.topology_table[(selector_ip, originator)] = {'seq_num': seq_num, 'last_updated': current_time}
            if header['ttl'] > 1 and sender_ip in self.mpr_selector_set:
                header['ttl'] -= 1
                forward_packet = {"messages": [{"message_header": header, "message_body": body}]}; forward_packet["packet_header"] = self._build_packet_header_unlocked()
                self._broadcast(json.dumps(forward_packet).encode('utf-8'))
    def _routing_table_thread(self):
        time.sleep(self.tc_interval + 0.5)
        while True:
            with self.table_lock: self._calculate_routing_table()
            time.sleep(self.routing_table_interval)
    def _calculate_routing_table(self):
        with self.table_lock:
            graph = {}; all_nodes = {self.my_ip} | set(self.neighbor_table.keys()) | {t[0] for t in self.topology_table} | {t[1] for t in self.topology_table}
            for node in all_nodes: graph[node] = set()
            for neighbor, data in self.neighbor_table.items():
                if data['status'] == 'SYM': graph[self.my_ip].add(neighbor); graph[neighbor].add(self.my_ip)
            for (dest, last) in self.topology_table:
                if dest in graph and last in graph: graph[last].add(dest)
            distances = {node: float('infinity') for node in all_nodes}; previous_nodes = {node: None for node in all_nodes}
            distances[self.my_ip] = 0; pq = [(0, self.my_ip)]
            while pq:
                dist, node = heapq.heappop(pq)
                if dist > distances[node]: continue
                for neighbor in graph.get(node, set()):
                    if distances[node] + 1 < distances[neighbor]:
                        distances[neighbor] = distances[node] + 1; previous_nodes[neighbor] = node
                        heapq.heappush(pq, (distances[neighbor], neighbor))
            new_routing_table = {};
            for dest_node, dist in distances.items():
                if dest_node == self.my_ip or dist == float('infinity'): continue
                path_node = dest_node
                while path_node and previous_nodes.get(path_node) != self.my_ip: path_node = previous_nodes.get(path_node)
                if path_node: new_routing_table[dest_node] = {'next_hop': path_node, 'distance': dist}
            self.routing_table = new_routing_table
    def _cleanup_thread(self):
        while True:
            time.sleep(self.hello_interval)
            with self.table_lock:
                current_time = time.time()
                neighbors_to_remove = [ip for ip, data in self.neighbor_table.items() if current_time - data['last_heard'] > self.neighbor_hold_time]
                two_hops_to_remove = [ip for ip, data in list(self.two_hop_table.items()) if (ip in self.neighbor_table or data['via_neighbor'] not in self.neighbor_table or current_time - data['last_updated'] > self.two_hop_hold_time)]
                tuples_to_remove = [t_tuple for t_tuple, data in self.topology_table.items() if current_time - data['last_updated'] > self.topology_hold_time]
                if neighbors_to_remove or two_hops_to_remove or tuples_to_remove:
                    for ip in neighbors_to_remove:
                        if ip in self.neighbor_table: del self.neighbor_table[ip]
                        self.mpr_selector_set.discard(ip)
                    for ip in set(two_hops_to_remove):
                        if ip in self.two_hop_table: del self.two_hop_table[ip]
                    for t_tuple in tuples_to_remove:
                        if t_tuple in self.topology_table: del self.topology_table[t_tuple]
                        self.last_tc_seq_nums.pop(t_tuple[1], None)
    def _mpr_selection_thread(self):
        while True:
            time.sleep(self.mpr_calculation_interval)
            with self.table_lock: self._calculate_mpr_set()
    def _calculate_mpr_set(self):
        self.mpr_set.clear()
        uncovered_2_hop_set = {ip for ip, data in self.two_hop_table.items() if data['via_neighbor'] in self.neighbor_table and self.neighbor_table[data['via_neighbor']]['status'] == 'SYM'}
        while uncovered_2_hop_set:
            best_candidate, max_coverage = None, 0
            mpr_candidates = {ip for ip, data in self.neighbor_table.items() if data['status'] == 'SYM'}
            for candidate in mpr_candidates:
                if candidate in self.mpr_set: continue
                reachable_by_candidate = {ip for ip, data in self.two_hop_table.items() if data['via_neighbor'] == candidate}
                coverage_set = reachable_by_candidate.intersection(uncovered_2_hop_set)
                if len(coverage_set) > max_coverage:
                    max_coverage, best_candidate = len(coverage_set), candidate
            if best_candidate is None: break
            self.mpr_set.add(best_candidate)
            newly_covered = {ip for ip, data in self.two_hop_table.items() if data['via_neighbor'] == best_candidate}
            uncovered_2_hop_set -= newly_covered