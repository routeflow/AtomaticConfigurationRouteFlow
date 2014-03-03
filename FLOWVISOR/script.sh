sudo ip link add veth1 type veth peer name veth2
ifconfig veth2 162.168.11.2 netmask 255.255.255.255 up
ifconfig veth1 162.168.11.1 netmask 255.255.255.255 up

