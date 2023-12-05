#!/usr/bin/python
import yaml

def get_ceph_details(ceph_disk_details, host_name):
    file_name = "/tmp/osd-maintenance/osd_details.json" + "_" + host_name
    try:
        with open(file_name, 'r') as outfile:
            data = yaml.safe_load(outfile)
    except Exception, e:
        raise Exception(
            "YAML upload of OSD details failed: {0}".format(str(e)))

    num_total_elements = len(ceph_disk_details)
    for i in range(0, num_total_elements):
        if 'partitions' in ceph_disk_details[i]:
            if (ceph_disk_details[i]['partitions'][0]['type'] == 'data' and \
                ceph_disk_details[i]['partitions'][0]['cluster'] == 'ceph'):
                osd_id = ceph_disk_details[i]['partitions'][0]['whoami']
                osd_state = str(ceph_disk_details[i]['partitions'][0]['state'])
                osd_path = str(ceph_disk_details[i]['partitions'][0]['path'])
                osd_blk = osd_path.strip("/dev/")
                osd_mount = str(ceph_disk_details[i]['partitions'][0]['mount'])
                journal_types = ['block.db_dev', 'block_dev', 'journal_dev']
                for journal_type in journal_types:
                    if journal_type in ceph_disk_details[i]['partitions'][0]:
                        osd_journal = str(ceph_disk_details[i]['partitions'][0][journal_type])
                        break

                for j in range(0, len(data)):
                    if int(data[j]['id_num']) == int(osd_id):
                        data[j]['osd_state'] = str(osd_state)
                        data[j]['osd_path'] = str(osd_path)
                        data[j]['osd_blk'] = str(osd_blk)
                        data[j]['osd_mount'] = str(osd_mount)
                        data[j]['osd_journal'] = str(osd_journal)
                        break

    with open(file_name, 'w') as outfile:
        outfile.write("OSD: ")
        outfile.write(str(data))
        outfile.write("\n")
        outfile.write("Number_of_OSDS: ")
        outfile.write(str(len(data)))
        outfile.write("\n")

    return ceph_disk_details

class FilterModule(object):
    ''' A filter to return a dictionary of port-channel status '''
    def filters(self):
        return {
            'get_ceph_details': get_ceph_details
        }
