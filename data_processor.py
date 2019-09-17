__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Johnson, Will", "Gannon, Connor",
               "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@students.tntech.edu"
__status__ = "Prototype"


# Importing the libraries
import json
import numpy as np
import pandas as pd
import logging 


# Parsing data from the production JSON dataset
json_file = open('../dataset/raw/t1/suricata_http.json')
data = json.load(json_file)
json_file.close()


# Declaring the global variables
cols_name_alert = [
                    '_indextime', 'host', '_time', 'flow_id',
                    'action', 'category', 'gid', 'rev', 'severity',
                    'signature', 'signature_id', 'dest_ip', 'dest_port',
                    'tx_id', 'in_iface', 'payload', 'packet',
                    'proto', 'src_ip', 'src_port', 'hostname',
                    'http_content_type', 'http_user_agent',
                    'length', 'protocol', 'status', 'url', 'team'
                   ]

cols_name_http = [
                    '_indextime', 'host', '_time', 'flow_id',
                    'dest_ip', 'dest_port', 'tx_id', 'in_iface',
                    'proto', 'src_ip', 'src_port', 'hostname',
                    'http_content_type', 'http_user_agent',
                    'http_method', 'length', 'protocol',
                    'status', 'url', 'team'
                 ]

alertDataFrame = np.ndarray([len(data),len(cols_name_alert)])
alertDataFrame = alertDataFrame.astype(str)
alertTemp = ['nan' for i in range(len(cols_name_alert))]

httpDataFrame = np.ndarray([len(data),len(cols_name_http)])
httpDataFrame = alertDataFrame.astype(str)
httpTemp = ['nan' for i in range(len(cols_name_http))]

rowIndexToInsertNDArray = 0


# Get the column index
def chcekColumnName(key):
    
    len_cols_name_alert = len(cols_name_alert)
    for i in range(0, len_cols_name_alert):
        if(key == cols_name_alert[i]):
            return i #returning the existing column value
    
    return -1 # No column name exists    


# Copy temp list to the main dataframe
def loadToMainDataFrame():
    for i in range(0, len(cols_name_alert)):
        if(alertTemp[i] == 'nan'):
            alertDataFrame[rowIndexToInsertNDArray][i] = np.nan
        else:
            alertDataFrame[rowIndexToInsertNDArray][i] = alertTemp[i]


# Main processor engine for suricata alert JSON file
def processIDSAlert():
    # Referencing global variables
    global rowIndexToInsertNDArray
    global alertTemp
    
    for d in data:
        for attribute in d:
            if(attribute == "_raw"):
                data_raw = json.loads(d[attribute])
                
                for item in data_raw:
                    
                    try:
                        if(item == 'alert'):
                            for key in data_raw['alert']:
                                i = chcekColumnName(key)
                                if(i != -1):
                                    alertTemp[i] = data_raw['alert'][key]
                                    
                    except:
                        logging.exception('no alert found\n', exc_info=True)
                    
                    try:
                        if(item == 'http'):
                            for key in data_raw['http']:
                                i = chcekColumnName(key)
                                if(i != -1):
                                    alertTemp[i] = data_raw['http'][key]
                                
                    except:
                        logging.exception('no http found\n', exc_info=True)
                    
                    i = chcekColumnName(item)
                    if(i != -1):
                        alertTemp[i] = data_raw[item]
            
            index = chcekColumnName(attribute)
            if(index != -1):
                alertTemp[index] = d[attribute]
            
        alertTemp[-1] = 9 # Team number is 1        
        loadToMainDataFrame()
        rowIndexToInsertNDArray = rowIndexToInsertNDArray + 1
        alertTemp.clear()
        alertTemp = ['nan' for i in range(len(cols_name_alert))]


        
processIDSAlert()    
# Generating the CSV file for further usuage.            
pd.DataFrame(alertDataFrame).to_csv("../suricata_alert_log_t9.csv")