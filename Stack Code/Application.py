# application.py
# The main application demonstrating a client/server model using the virtual stack.

import time
import threading
import random
from datetime import datetime  # <<< ADD THIS LINE
# Import the two lower layers of our virtual stack
from network import OlsrNode
from transport import VirtualUDP

# =================================================================
#  >>> CONFIGURE THE EXPERIMENT HERE <<<
# =================================================================
MY_IP_ADDRESS = '192.168.10.1' 
SERVER_IP = '192.168.10.1'

# Standard port numbers for Echo and Time services
ECHO_PORT = 7
TIME_PORT = 13

# =================================================================
#  >>> APPLICATION LOGIC (SERVER-SIDE) <<<
# =================================================================

def run_server_logic(transport_layer: VirtualUDP):
    """Binds to ports and listens for requests."""
    
    # Bind the application logic to specific virtual ports
    transport_layer.bind(ECHO_PORT)
    transport_layer.bind(TIME_PORT)
    
    print(f"[Application Layer] Server is running. Listening on ports {ECHO_PORT} (Echo) and {TIME_PORT} (Time).")

    while True:
        # Check the Echo port for incoming data
        (source_addr, data) = transport_layer.recvfrom(ECHO_PORT)
        if data:
            print(f"[App Server] Received '{data}' on port {ECHO_PORT} from {source_addr[0]}:{source_addr[1]}. Sending echo back.")
            # Echo the data back to the sender's source port
            transport_layer.sendto(source_addr[0], source_addr[1], data)

        # Check the Time port for incoming data
        (source_addr, data) = transport_layer.recvfrom(TIME_PORT)
        if data:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[App Server] Received time request on port {TIME_PORT} from {source_addr[0]}:{source_addr[1]}. Sending time back.")
            # Send the current time back to the sender's source port
            transport_layer.sendto(source_addr[0], source_addr[1], current_time)
            
        time.sleep(0.1) # Prevents the loop from consuming 100% CPU

# =================================================================
#  >>> APPLICATION LOGIC (CLIENT-SIDE) <<<
# =================================================================

# In application.py

# =================================================================
#  >>> REPLACE THE OLD run_client_tasks WITH THIS NEW VERSION <<<
# =================================================================
def run_client_tasks(transport_layer: VirtualUDP):
    """Runs on client nodes. Periodically sends requests to the server in a loop."""
    
    # Choose a random ephemeral port for receiving replies. This is done only once.
    client_port = random.randint(49152, 65535)
    transport_layer.bind(client_port)
    print(f"[Application Layer] Client is running. Will use source port {client_port} for all communication.")
    
    # Wait for the network to be fully stable before starting the loop.
    print("Waiting for initial route discovery...")
    time.sleep(25) 

    packet_counter = 0
    while True:
        try:
            packet_counter += 1
            print(f"\n--- Sending Request Set #{packet_counter} ---")

            # --- Test 1: Echo Service ---
            message_to_echo = f"Hello from {MY_IP_ADDRESS}, packet #{packet_counter}"
            transport_layer.sendto(SERVER_IP, ECHO_PORT, message_to_echo, source_port=client_port)
            print(f"CLIENT: Sent '{message_to_echo}' to {SERVER_IP}:{ECHO_PORT}")

            # --- Test 2: Time Service ---
            transport_layer.sendto(SERVER_IP, TIME_PORT, "time_request", source_port=client_port)
            print(f"CLIENT: Sent time request to {SERVER_IP}:{TIME_PORT}")
            
            # --- Wait for replies ---
            # We will wait for a short period to see if replies come back.
            # In a real app, you might handle this in a separate receiving thread.
            print("CLIENT: Waiting for replies...")
            time.sleep(3) # Give 3 seconds for replies to arrive

            # Check the receive queue for any messages that arrived.
            while True:
                (source_addr, data) = transport_layer.recvfrom(client_port)
                if data:
                    # Check if it's a reply from the server
                    if source_addr and source_addr[0] == SERVER_IP:
                        # We don't know if it's an echo or time reply, so just print it
                        print(f"CLIENT: Received reply: '{data}'")
                else:
                    # No more messages in the queue
                    break
            
            # Wait for the next cycle
            time.sleep(5) # Wait 5 seconds before sending the next set of requests

        except KeyboardInterrupt:
            # Allow the user to exit the loop cleanly
            print("\nClient task shutting down.")
            break
        except Exception as e:
            print(f"An error occurred in client task: {e}")
            time.sleep(5) # Wait before retrying
# =================================================================
#  >>> MAIN EXECUTION BLOCK <<<
# =================================================================
if __name__ == "__main__":
    am_i_server = (MY_IP_ADDRESS == SERVER_IP)
    
    # 1. Initialize the Network Layer (OLSR)
    network_layer = OlsrNode(my_ip=MY_IP_ADDRESS)
    
    # 2. Initialize the Transport Layer, giving it the network layer
    transport_layer = VirtualUDP(network_layer)

    # 3. Start the OLSR protocol in a background thread
    print("Initializing OLSR protocol in the background...")
    olsr_thread = threading.Thread(target=network_layer.start, daemon=True)
    olsr_thread.start()
    
    print("Waiting for OLSR to stabilize...")
    time.sleep(20) # Give OLSR time to build tables

    # 4. Start the Application task based on the node's role
    try:
        if am_i_server:
            run_server_logic(transport_layer)
        else:
            run_client_tasks(transport_layer)
    except KeyboardInterrupt:
        print("\nApplication shutting down.")
    except Exception as e:
        print(f"A critical application error occurred: {e}")