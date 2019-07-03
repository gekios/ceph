set -x
ceph osd out 0 1 2
ceph osd in 0 1 2
ceph osd out 0 1 2
ceph osd in 0 1 2
ceph osd out 0 1 2
ceph -s
ceph osd in 0 1 2
ceph osd out 0 1 2
ceph osd in 0 1 2
ceph -s
sleep 60
ceph -s
ceph osd out 0 1 2
ceph osd in 0 1 2
ceph osd out 0 1 2
ceph osd in 0 1 2
ceph osd out 0 1 2
ceph -s
ceph osd in 0 1 2
ceph osd out 0 1 2
ceph osd in 0 1 2
sleep 60 
ceph -s
sleep 600
ceph -s

