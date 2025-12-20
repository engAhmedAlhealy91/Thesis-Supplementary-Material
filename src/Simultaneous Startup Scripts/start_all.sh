#!/bin/bash

echo "--- Starting OLSR on all nodes in PARALLEL ---"

NODE_IPS=(
    "ras1@192.168.0.101"
    "ras2@192.168.0.102"
    "ras3@192.168.0.103"
    "ras4@192.168.0.104"
    "ras5@192.168.0.105"
)

REMOTE_COMMAND="cd ~/Desktop && python3 final44.py"

for NODE in "${NODE_IPS[@]}"
do
    echo "Sending start command to node ${NODE}..."
    # The '&' at the end of the ssh command runs IT in the background on YOUR laptop.
    # This means the loop doesn't wait and immediately starts the next one.
    ssh ${NODE} "nohup bash -c '${REMOTE_COMMAND}' > /dev/null 2>&1 &" &
done

# Wait for all the background SSH processes to finish initiating.
# This is good practice to ensure all commands have been sent.
wait

echo "--- All OLSR nodes have been sent the start command. ---"