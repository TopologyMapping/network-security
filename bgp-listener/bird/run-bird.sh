#!/bin/bash
set -eu

NS_NAME="bgpns"
VETH_HOST="veth0"
HOST_IP="10.0.0.3/24"
VETH_NS="veth1"
NS_IP="10.0.0.2/24"

# Create namespace
ip netns add $NS_NAME

# Create veth pair
ip link add $VETH_HOST type veth peer name $VETH_NS

# Move veth1 into namespace
ip link set $VETH_NS netns $NS_NAME

# Configure host side
ip addr add $HOST_IP dev $VETH_HOST
ip link set $VETH_HOST up

# Configure namespace side
ip netns exec $NS_NAME ip addr add $NS_IP dev $VETH_NS
ip netns exec $NS_NAME ip link set $VETH_NS up
ip netns exec $NS_NAME ip link set lo up

# Run BIRD
ip netns exec $NS_NAME bird -c bird.conf -s bird.ctl

echo "Connect to BIRD with [ birdc -s bird.ctl ]"
echo "Close BIRD by running [ down ] inside birdc"
echo "Cleanup namespace and veth with [ ip netns del $NS_NAME ]"
