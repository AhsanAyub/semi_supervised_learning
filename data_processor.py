__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Johnson, Will", "Gannon, Connor",
               "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@students.tntech.edu"
__status__ = "Prototype"

import os
import glob
import json
# import pandas as pd

dir_name = "../dataset/raw/t1"
os.chdir(dir_name)

extension = 'json'
all_filenames = [i for i in glob.glob('*.{}'.format(extension))]

# Parsing data from the production JSON dataset
json_file = open(all_filenames[4])
data = json.load(json_file)
json_file.close()

cols_name_alert = [
                    'indextime', 'host', 'time', 'action',
                    'category', 'gid', 'rev', 'severity',
                    'signature', 'signature_id', 'dest_ip',
                    'dest_port', 'alert', 'flow_id', 'in_iface',
                    'payload', 'packet', 'proto', 'src_ip',
                    'src_ip', 'src_port', 'hostname',
                    'http_consent_type', 'http_user_agent',
                    'http_user_agent', 'length', 'protocol',
                    'status', 'url'
                   ]

count = 0
count_http = 0

for d in data:
    data_raw = json.loads(d["_raw"])
    try:
        if(len(data_raw['alert']) != 7):
            print(data_raw['alert'])        
            
        if(len(data_raw['app_proto']) == 8):
            print(data_raw['app_proto'])
        
        if(data_raw['app_proto'] == 'http'):
            count_http = count_http + 1
    except:
        if(count < 1):
            print(d)
        count = count + 1