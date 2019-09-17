# iSCSI Gateway smoke test
#
# takes an optional argument, --upgrade, which triggers slightly different
# behavior, for testing post-upgrade sanity of the iSCSI Gateway

UPGRADE=""
if [[ $* == *--upgrade* ]]; then
    UPGRADE="--upgrade"
    echo "Upgrade mode: testing post-upgrade sanity of the iSCSI Gateway"
fi

if [ "$UPGRADE" ] ; then
    # post-upgrade sanity test
    set -ex
else
    # ordinary SES5 (non-upgrade) test
    set -x
    rpm -q lrbd
    lrbd --output
    ls -lR /sys/kernel/config/target/
    ss --tcp --numeric state listening
    echo "See 3260 there?"
    set -e
    zypper --non-interactive --no-gpg-checks install \
        --force --no-recommends open-iscsi
    systemctl start iscsid.service
    sleep 5
    systemctl --no-pager --full status iscsid.service
fi

# Find out ipv4 address of the first non-localhost network device.
# We can't use this because ip -j is not supported yet for sle12-sp3
#   my_ip=$(ip -4 -j a show |
#           jq -r '[.[]|select(."ifname" != "lo")][0] |.addr_info[]|.local')
# Using brief format, for example:
#   lo               UNKNOWN        127.0.0.1/8
#   eth0             UP             192.168.0.1/24
first_non_lo_dev=($(ip -4 -br a | grep -v ^lo | head -1))
my_ip=${first_non_lo_dev[2]%/*}
iscsiadm -m discovery -t st -p $my_ip
iscsiadm -m node -L all
sleep 5
ls -l /dev/disk/by-path
ls -l /dev/disk/by-*id

if [  "$UPGRADE" ]; then
    # post-upgrade sanity test
    test -d /mnt
    mount /dev/disk/by-path/*iscsi* /mnt
    df -h /mnt
    test -s /mnt/bubba
    echo sanity_test > /mnt/testfile
    test -s /mnt/testfile
else
    # ordinary SES5 (non-upgrade) test
    if ( mkfs -t xfs /dev/disk/by-path/*iscsi* ) ; then
        :
    else
        dmesg
        false
    fi
    test -d /mnt
    mount /dev/disk/by-path/*iscsi* /mnt
    df -h /mnt
    echo hubba > /mnt/bubba
    test -s /mnt/bubba
fi

umount /mnt
iscsiadm -m node --logout
echo "OK" >/dev/null
