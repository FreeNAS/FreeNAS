#!/bin/sh
#+
# Copyright 2011 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################


zfs_opt() { echo z; }
zfs_help() { echo "Dump ZFS Configuration"; }
zfs_directory() { echo "ZFS"; }
zfs_getacl()
{
	local ds="${1}"
	local parameter
	local val
	local mp

	zfs get -H -o property,value mounted,mountpoint,acltype "${ds}" | while read -r s
	do
		parameter=$(echo -n "$s" | awk '{print $1}' | tr -d '\n')
		val=$(echo -n "$s" | awk '{print $2}' | tr -d '\n')
		case "${parameter}" in
		mountpoint)
			if [ "${val}" = "legacy" ] || [ "${val}" = "-" ]; then
				return 0
			fi
			mp=$(echo -n "${val}")
			;;
		mounted)
			if [ "${val}" = "no" ] || [ "${val}" = "-" ]; then
				return 0
			fi
			;;
		acltype)
			echo "Mountpoint ACL: ${ds}"
			if [ ${val} = "nfsv4" ]; then
				nfs4xdr_getfacl "${mp}"
			else
				getfacl "${mp}"
			fi
			;;
		*)
			echo "Unexpected parameter: ${parameter}"
			return 0
			;;
		esac
	done

	return 0
}

zfs_func()
{
	section_header "zfs periodic snapshot tasks"
	${FREENAS_SQLITE_CMD} ${FREENAS_CONFIG} -line "
	SELECT *
	FROM storage_task
	ORDER BY +id"
	section_footer

	section_header "zfs replication tasks"
	${FREENAS_SQLITE_CMD} ${FREENAS_CONFIG} -line "
	SELECT *
	FROM storage_replication
	ORDER BY +id"
	section_footer

	section_header "zfs replication tasks to periodic snapshot tasks"
	${FREENAS_SQLITE_CMD} ${FREENAS_CONFIG} -line "
	SELECT *
	FROM storage_replication_repl_periodic_snapshot_tasks
	ORDER BY +id"
	section_footer

	section_header "zpool scrub"
	${FREENAS_SQLITE_CMD} ${FREENAS_CONFIG} -line "
	SELECT *
	FROM storage_scrub
	WHERE id >= '1'
	ORDER BY +id"
	section_footer
	
	section_header "zpool list"
	zpool list
	section_footer

	section_header "zfs list -ro space,refer,mountpoint"
	zfs list -ro space,refer,mountpoint
	section_footer

	section_header "zpool status -v"
	zpool status -v
	section_footer

	section_header "zpool history"
	zpool history
	section_footer

	section_header "zpool history -i | tail -n 1000"
	zpool history -i | tail -n 1000
	section_footer

	section_header "zpool get all"
	pools=$(zpool list -H|awk '{ print $1 }'|xargs)
	for p in ${pools}
	do
		section_header "${p}"
		zpool get all ${p}
		section_footer
	done
	section_footer

	section_header "zfs list -t snapshot"
	zfs list -t snapshot -o name,used,available,referenced,mountpoint,freenas:state
	section_footer

	section_header "zfs get all"
	zfs list -o name -H | while read -r s
	do
		section_header "${s}"
		zfs get all "${s}"
		zfs_getacl "${s}"
		section_footer
	done
	section_footer

	section_header "lsblk -o NAME,FSTYPE,LABEL,UUID,PARTUUID -l -e 230"
	lsblk -o NAME,FSTYPE,LABEL,UUID,PARTUUID -l -e 230
	section_footer
	section_header  "zpool status -v"
	zpool status -v
	section_footer
	section_header  "zpool status -g"
	zpool status -g
	section_footer

	for pool in $(zpool list -Ho name | grep -v -e "$(midclt call boot.pool_name)"); do
		section_header "${pool} Pool Encryption Summary"
		midclt call -job -jp description pool.dataset.encryption_summary "${pool}" | jq .
		section_footer
	done
}
