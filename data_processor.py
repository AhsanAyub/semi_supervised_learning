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
json_file = open('../dataset/raw/t7/suricata_http.json')

'''with open('../dataset/raw/t8/suricata_http.json') as json_file:      
    jsonData = json_file.readlines()
    # this line below may take at least 8-10 minutes of processing for 4-5 million rows. It converts all strings in list to actual json objects. 
    jsonData = list(map(json.loads, jsonData))
    
jsonData = pd.DataFrame(jsonData)

data = []

for i in range(0,492304):
    jsonData.append(data[i][0].copy())'''
    
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
httpDataFrame = httpDataFrame.astype(str)
httpTemp = ['nan' for i in range(len(cols_name_http))]

rowIndexToInsertNDArray = 0


# Get the column index
def chcekColumnName(key):
    
    # len_cols_name = len(cols_name_alert)
    len_cols_name = len(cols_name_http)
    for i in range(0, len_cols_name):
        #if(key == cols_name_alert[i]):
        if(key == cols_name_http[i]):
            return i #returning the existing column value
    
    return -1 # No column name exists    


# Copy temp list to the main dataframe
def loadToMainDataFrame():
    for i in range(0, len(cols_name_http)):    
        if(httpTemp[i] == 'nan'):
            httpDataFrame[rowIndexToInsertNDArray][i] = np.nan
        else:
            httpDataFrame[rowIndexToInsertNDArray][i] = httpTemp[i]
            
    '''for i in range(0, len(cols_name_alert)):
        if(alertTemp[i] == 'nan'):
            alertDataFrame[rowIndexToInsertNDArray][i] = np.nan
        else:
            alertDataFrame[rowIndexToInsertNDArray][i] = alertTemp[i]'''
            
    


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


# Main processor engine for suricata http JSON file
def processIDSHTTPLog():
    # Referencing global variables
    global rowIndexToInsertNDArray
    global httpTemp
    
    for d in data:
        for attribute in d:
            if(attribute == "_raw"):
                data_raw = json.loads(d[attribute])
                
                for item in data_raw:
                    try:
                        if(item == 'http'):
                            for key in data_raw['http']:
                                i = chcekColumnName(key)
                                if(i != -1):
                                    httpTemp[i] = data_raw['http'][key]
                                
                    except:
                        logging.exception('no http found\n', exc_info=True)
                    
                    i = chcekColumnName(item)
                    if(i != -1):
                        httpTemp[i] = data_raw[item]
            
            index = chcekColumnName(attribute)
            if(index != -1):
                httpTemp[index] = d[attribute]
            
        httpTemp[-1] = 7 # Team number is 1        
        loadToMainDataFrame()
        rowIndexToInsertNDArray = rowIndexToInsertNDArray + 1
        httpTemp.clear()
        httpTemp = ['nan' for i in range(len(cols_name_http))]

       
processIDSAlert()    
processIDSHTTPLog()

# Generating the CSV file for further usuage.            
pd.DataFrame(alertDataFrame).to_csv("../suricata_alert_log_t9.csv")
pd.DataFrame(httpDataFrame).to_csv("../suricata_http_log_t7.csv")