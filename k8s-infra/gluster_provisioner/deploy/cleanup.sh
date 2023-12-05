#This uses the gluster_deploy script to delete all the Gluster related
#Services and Pods
#Path based cleanup should be done on all the hosts in case of new install
#Volume_Groups have to be deleted properly using "vgdisplay and vgremove"
#Clear any existing signatures using "wipefs -fa /dev/sda"
./gluster-deploy -g -y --abort;
rm -rf /var/lib/heketi \
   /etc/glusterfs \
   /var/lib/glusterd \
   /var/log/glusterfs
sudo rm -rf /var/lib/heketi
sudo rm -rf /etc/glusterfs
sudo rm -rf /var/log/glusterfs
sudo rm -rf /var/lib/glusterd
sudo rm -rf /var/lib/misc/glusterfsd
