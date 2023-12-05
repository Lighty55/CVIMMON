#!/usr/bin/python
import yaml

def get_osd_details(osd_tree_details):
    num_total_elements = len(osd_tree_details['nodes'])
    files_created = 0
    for i in range(0, num_total_elements):
        if osd_tree_details['nodes'][i]['type'] == "root":
            num_files_to_create = len(osd_tree_details['nodes'][i]['children'])
        elif osd_tree_details['nodes'][i]['type'] == "host":
            server_name = osd_tree_details['nodes'][i]['name']
            file_name = "/tmp/osd-maintenance/osd_details.json" + "_" + server_name
            num_osds = len(osd_tree_details['nodes'][i]['children'])
            osd_list = []
            # The next num_osds elements are all OSDs
            for j in range((i+1), (i+num_osds+1)):
                osd_dict = dict(name=str(osd_tree_details['nodes'][j]['name']),
                                id_num=int(osd_tree_details['nodes'][j]['id']),
                                status=str(osd_tree_details['nodes'][j]['status']),
                                d_type=str(osd_tree_details['nodes'][j]['type']),
                                d_host=str(server_name))
                osd_list.append(osd_dict)
            with open(file_name, 'a') as outfile:
                yaml.dump(osd_list, outfile)
    return osd_tree_details['nodes']

class FilterModule(object):
    ''' A filter to return a dictionary of port-channel status '''
    def filters(self):
        return {
            'get_osd_details': get_osd_details
        }
