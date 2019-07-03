set -x
ceph osd out 0 
ceph osd in 0  
ceph osd out 0  
ceph osd in 0  
ceph osd out 0  
ceph -s
ceph osd in 0  
ceph osd out 0  
ceph osd in 0  
ceph -s
sleep 60
ceph -s
ceph osd out 0  
ceph osd in 0  
ceph osd out 0  
ceph osd in 0  
ceph osd out 0  
ceph -s
ceph osd in 0  
ceph osd out 0  
ceph osd in 0  
sleep 60 
ceph -s
sleep 600
ceph -s

