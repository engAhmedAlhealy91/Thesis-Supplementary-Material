#!/bin/bash

echo "--- Stopping OLSR on all nodes ---"

NODE_IPS=(
    "ras1@192.168.0.101"
    "ras2@192.168.0.102"
    "ras3@192.168.0.103"
    "ras4@192.168.0.104"
    "ras5@192.168.0.105"
)

SCRIPT_NAME="final33.py"

# The command to find and kill the python process by its filename.
# We don't need sudo if the script was started by the user.
REMOTE_COMMAND="pkill -f ${SCRIPT_NAME}"

for NODE in "${NODE_IPS[@]}"
do
    echo "Stopping OLSR on node ${NODE}..."
    ssh ${NODE} "${REMOTE_COMMAND}"
done

echo "--- All OLSR nodes have been sent the stop command. ---"