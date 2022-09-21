#!/bin/sh
get_physical_disks_list()
{
	if is_linux; then
		lsblk -ndo path | grep -v '^/dev/sr'
	else
		sysctl -n kern.disks | tr ' ' '\n'| grep -v '^cd' \
			| sed 's/\([^0-9]*\)/\1 /' | sort +0 -1 +1n | tr -d ' '
	fi
}


hardware_opt() { echo h; }
hardware_help() { echo "Dump Hardware Configuration"; }
hardware_directory() { echo "Hardware"; }

hardware_linux()
{
	section_header "Hardware"

	echo "Machine class: $(uname -m)"

	echo "Machine model: $(lscpu | grep 'Model name' | cut -d':' -f 2 | sed -e 's/^[[:space:]]*//')"

	echo "Number of active CPUs: $(grep -c 'model name' /proc/cpuinfo)"

	echo "Number of CPUs online: $(lscpu -p=online | grep -v "^#" | grep -c "Y")"

	echo "Current CPU frequency: $(lscpu | grep 'CPU MHz' | cut -d':' -f 2 | sed -e 's/^[[:space:]]*//')"

	echo "Physical Memory: $(getconf -a | grep PAGES | awk 'BEGIN {total = 1} {if (NR == 1 || NR == 3) total *=$NF} END {print total / 1024 / 1024 / 1024" GiB"}')"

	section_footer

	section_header "lspci -vvvD"
	lspci -vvvD
	section_footer

	section_header "lshw -businfo"
	lshw -businfo
	section_footer

	section_header "lshw"
	lshw
	section_footer

	section_header "usb-devices"
	usb-devices
	section_footer

	section_header "dmidecode"
	dmidecode
	section_footer

	section_header "lsblk -o NAME,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,RQ-SIZE,RA,WSAME,HCTL"
	lsblk -o NAME,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,RQ-SIZE,RA,WSAME,HCTL
	section_footer

	for disk in $(get_physical_disks_list)
	do
		output=$(sg_vpd --page=di "$disk" 2> /dev/null)
		if [ $? -eq 0 ]; then
			section_header "sg_vpd --page=di $disk"
			echo "$output"
			section_footer
		fi
	done
}

hardware_freebsd()
{
	section_header "Hardware"

	desc=$(sysctl -nd hw.machine)
	out=$(sysctl -n hw.machine)
	echo "${desc}: ${out}"

	desc=$(sysctl -nd hw.machine_arch)
	out=$(sysctl -n hw.machine_arch)
	echo "${desc}: ${out}"

	desc=$(sysctl -nd hw.model)
	out=$(sysctl -n hw.model)
	echo "${desc}: ${out}"

	desc=$(sysctl -nd hw.ncpu)
	out=$(sysctl -n hw.ncpu)
	echo "${desc}: ${out}"

	desc=$(sysctl -nd kern.smp.cpus)
	out=$(sysctl -n kern.smp.cpus)
	echo "${desc}: ${out}"

	desc=$(sysctl -nd dev.cpu.0.freq)
	freq=$(sysctl -n dev.cpu.0.freq)
	out=$(echo "scale=4;${freq}/1024"|bc|xargs printf "%0.2f")
	echo "${desc}: ${out} Ghz"

	desc="Physical Memory"
	ram=$(sysctl -n hw.physmem)
	rram=$(echo "scale=4;${ram}/1024/1024/1024"|bc|xargs printf "%0.2f")
	echo "${desc}: ${rram} GiB"

	section_footer

	section_header "pciconf -lvcb"
	pciconf -lvcb
	section_footer

	section_header "devinfo -rv"
	devinfo -rv
	section_footer

	section_header "usbconfig list"
	usbconfig list
	section_footer

	section_header "dmidecode"
	dmidecode
	section_footer

	section_header "memcontrol list"
	memcontrol list
	section_footer

	section_header "camcontrol devlist -v"
	camcontrol devlist -v
	section_footer

	section_header "nvmecontrol devlist"
	nvmecontrol devlist
	section_footer

	for disk in $(get_physical_disks_list)
	do
		if echo "${disk}" | egrep -q '^da[0-9]+'
		then
			section_header "camcontrol inquiry ${disk}"
			camcontrol inquiry "${disk}"
			section_footer
		fi
	done

	for disk in $(get_physical_disks_list)
	do
		if echo "${disk}" | egrep -q '^ada[0-9]+'
		then
			section_header "camcontrol identify ${disk}"
			camcontrol identify "${disk}"
			section_footer
		fi
	done

	#
	#	This logic is being moved to the IPMI module
	#	because we are running duplicate ipmitool commands
	#
	#if [ -c /dev/ipmi0 ]
	#then
	#	for list_type in sel sdr
	#	do
	#		section_header "ipmitool $list_type list"
	#		ipmitool $list_type list
	#		section_footer
	#	done
	#fi

	if which getencstat > /dev/null
	then
		section_header "getencstat -V /dev/ses*"
		getencstat -V /dev/ses*
		section_footer
	fi

	if [ -c /dev/mps0 ]; then
		section_header "sas2flash -listall"
		sas2flash -listall
		section_footer
	fi

	if [ -c /dev/mpr0 ]; then
		section_header "sas3flash -listall"
		sas3flash -listall
		section_footer
	fi

	if midclt call truenas.get_chassis_hardware | grep -q TRUENAS-M; then
		for nvdimm in /dev/nvdimm*; do
			section_header "M-Series NVDIMM $nvdimm"
			ixnvdimm $nvdimm
			section_footer
		done
	fi

	section_header "Enclosures (midclt call enclosure.query)"
	midclt call enclosure.query |jq .
	section_footer
}

hardware_func()
{
	if is_linux; then
		hardware_linux
	else
		hardware_freebsd
	fi
}
