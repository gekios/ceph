# iSCSI Gateway smoke test
set -x

# Added optional --upgrade argument which checks the existing
# file that was created and created a new one
TEMP=$(getopt -o h --long "upgrade" -- "$@")
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi
UPG=false
eval set -- "$TEMP"
while true ; do
    case "$1" in
        --upgrade | --up) UPG=true ; shift ;;
        --) shift ; break ;;
        *) echo "Internal error" ; false ;;
    esac
done

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
if [  "$UPG" = false ]; then
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
else
  test -d /mnt
  mount /dev/disk/by-path/*iscsi* /mnt
  df -h /mnt
  test -s /mnt/bubba
  echo sanity_test > /mnt/testfile
  test -s /mnt/testfile
fi
umount /mnt
iscsiadm -m node --logout
echo "OK" >/dev/null
