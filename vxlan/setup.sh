#!/usr/bin/env bash
#
#
set -x

VRF="BLUE"
REMOTE_SUBNET="10.254.34.0/29"
LOCAL_SUBNET="10.20.20.0/24"
INSIDE_IP="10.254.12.2"
OUTSIDE_IP="10.20.20.2"

CORE_INTERFACE="eth1"
DOWNSTREAM_INTERFACE="eth0"

echo "applying progs to interfaces"
./xdp_loader -F --dev ${CORE_INTERFACE} --filename xdp_prog_kern_vxlan.o --progsec xdp_sb
./xdp_loader -F --dev ${DOWNSTREAM_INTERFACE} --filename xdp_prog_kern_vxlan.o --progsec xdp_nb


echo "setting up remote vtep"

remote_rmac=$(vtysh -c "sh bgp l2vpn evpn ${REMOTE_SUBNET}" | grep -oE "Rmac:\S+" | sed 's/Rmac://')
if [[ -z "$remote_rmac" ]]; then
	echo "could not get remote Rmac"
	exit 1
fi

echo "Remote Rmac: $remote_rmac"

local_rmac=$(vtysh -c "sh bgp l2vpn evpn ${LOCAL_SUBNET}" | grep -oE "Rmac:\S+" | sed 's/Rmac://')
if [[ -z "$local_rmac" ]]; then
	echo "could not get local Rmac"
	exit 1
fi

echo "Local Rmac: $local_rmac"

echo "getting ifindex and mac address for core interface"

ifindex=$(ip link show ${CORE_INTERFACE} | grep ${CORE_INTERFACE} | sed 's/:.*//')
if [[ -z "$ifindex" ]]; then
	echo "could not get ifindex for ${CORE_INTERFACE}"
	exit 1
fi

echo "Core ifindex: $ifindex"

core_mac=$(ip link show ${CORE_INTERFACE} | grep ether | awk '{print $2}')
if [[ -z "$core_mac" ]]; then
	echo "could not get core_mac for ${CORE_INTERFACE}"
	exit 1
fi

echo "Core mac: $core_mac"

./xdp_prog_user_nat -d ${DOWNSTREAM_INTERFACE} -l ${INSIDE_IP} -g ${OUTSIDE_IP}
./xdp_prog_user_nat -d ${CORE_INTERFACE} -l ${INSIDE_IP} -g ${OUTSIDE_IP}

./xdp_prog_user_mac_rewrite -d ${CORE_INTERFACE} -L ${local_rmac} -R ${core_mac}

