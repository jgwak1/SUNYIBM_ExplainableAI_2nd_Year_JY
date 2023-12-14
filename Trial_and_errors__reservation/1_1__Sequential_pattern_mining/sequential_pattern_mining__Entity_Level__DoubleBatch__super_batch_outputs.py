# a)	Sequential pattern mining: 

# Treating log entries as time series data, we perform sequential pattern mining 
# to identify event sequences that appear at statistically significant frequencies in the event logs. 

# We will first try standard sequential pattern mining algorithms, such as the GSP algorithm, in this task; 
# if they do not perform well, we will consider developing our own algorithms for it.  

# When performing sequential pattern mining, 
# we need to analyze not only the operation types of the events but also their arguments. ***
# Consider a scenario where a thread opens File A and then writes to File B. 
# These two events should not be grouped into the same event sequence because they are performed on different files. 

# The computation graph derived from the event logs (see Figure 1) 
# can be utilized to facilitate the task of sequential pattern mining, 
# because the relevant entities have already been extracted from each system event recorded in the log. 

# ##########################################################################################################3
# JY Thoughts:
 
# > Event-sequences with statistically significant frequencies "within" and/or "across" (malicious? or both?) event-logs?
# > GSP -- https://github.com/jacksonpradolima/gsp-py

'''
TODO-3: “For the same entity (e.g. file A), say, “create” events only provide “filename” attribute, 
and “close” events only provide “fileobject”. We addressed it (but not completely), 
which may affect this approach.”   있는걸로 어쨌든하기 

참고 : /data/d1/jgwak1/tabby/STREAMLINED_DATA_GENERATION_MultiGraph/STEP_2_Benign_NON_TARGETTED_SUBGRAPH_GENERATION_GeneralLogCollection_subgraphs/model_v3_PW/FirstStep.py

'''

import json
from pathlib import Path
import sys
import os
sys.path.append( str(Path(__file__).resolve().parent.parent.parent / "Datasets") ) 

from elasticsearch import Elasticsearch, helpers
import datetime
import gc

# -- There exists "PrefixSpan" python-implementation, but likely too slow as well: https://github.com/chuanconggao/PrefixSpan-py
from gsppy.gsp import GSP  # too slow


# https://github.com/fidelity/seq2pat/blob/master/notebooks/sequential_pattern_mining.ipynb
# https://fidelity.github.io/seq2pat/index.html
from sequential.seq2pat import Seq2Pat, Attribute
import random
import numpy as np


import psutil
import pickle
import os
# Inside your loop or at key points in your code


FILE_PROVIDER = "EDD08927-9CC4-4E65-B970-C2560FB5C289"
NETWORK_PROVIDER = "7DD42A49-5329-4832-8DFD-43D979153A88"
PROCESS_PROVIDER = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716"
REGISTRY_PROVIDER = "70EB4F03-C1DE-4F73-A051-33D13D5413BD"




def flatten_all_hits( all_hits ): 
   # all_hits == result['hits']['hits']

   def flatten_dict(d, parent_key='', sep='_'):
      items = {}
      for key, value in d.items():
         new_key = f"{parent_key}{sep}{key}" if parent_key else key
         if isinstance(value, dict):
               items.update(flatten_dict(value, new_key, sep=sep))
         else:
               items[new_key] = value
      return items


   all_hits_flatten = []
   for hit in all_hits:
            event_original_data = json.loads(hit['_source']['event']['original'])

            # Flatten the dictionary
            flattened_data = flatten_dict(hit)
            flattened_data['_source_event_original'] = event_original_data  # Add the parsed 'original' data
            flattened_event_original = flatten_dict(event_original_data, 'event_original')
            
                  # Update the flattened_data with the flattened_event_original
            flattened_data.update(flattened_event_original)
            flattened_data.pop('_source_event_original',None)
            all_hits_flatten.append(flattened_data)
   return all_hits_flatten

# Registry: 
# EventID(1)-(Opcode:32 Opcodename:Createkey), 
# EventID(2)-(Opcode:33 Opcodename:Openkey),
# EventID(3)-(Opcode:34 Opcodename:Deletekey), 
# EventID(4)-(Opcode:35 Opcodename:Querykey), 
# EventID(5)( Opcode:36, OpcodeName: SetValueKey), 
# EventID(6)( Opcode:37, Opcodename: DeleteValueKey), 
# EventID(7)-(Opcode:38 Opcodename:QueryValueKey),  
# EventID(8)-(Opcode:39, Opcodename:EnumerateKey), 
# EventID(9)-(Opcode:40 Opcodename: EnumerateValuekey), 
# EventID(10)-(Opcode:41 Opcodename: QueryMultipleValuekey),
# EventID(11)-(Opcode:42 Opcodename: Setinformationkey), 
# EventID(13)-(Opcode:44 Opcodename:Closekey), 
# EventID(14)-(Opcode:45 Opcodename: QuerySecuritykey),
# EventID(15)-(Opcode:46 Opcodename: SetSecuritykey), 
# Thisgroupofeventstrackstheperformanceofflushinghives - (opcode 13,OpcodeName:RegPerfOpHiveFlushWroteLogFile)

RegistryProvider_EventID_2_HumanReadable_Map = {
      "EventID(1)": "Registry_Createkey",
      "EventID(2)": "Registry_Openkey",
      "EventID(3)": "Registry_Deletekey",
      "EventID(4)": "Registry_Querykey",
      "EventID(5)": "Registry_SetValueKey",
      "EventID(6)": "Registry_DeleteValueKey",
      "EventID(7)": "Registry_QueryValueKey",
      "EventID(8)": "Registry_EnumerateKey",
      "EventID(9)": "Registry_EnumerateValuekey",
      "EventID(10)": "Registry_QueryMultipleValuekey",
      "EventID(11)": "Registry_Setinformationkey",
      "EventID(13)": "Registry_Closekey",
      "EventID(14)": "Registry_QuerySecuritykey",
      "EventID(15)": "Registry_SetSecuritykey",
      "Thisgroupofeventstrackstheperformanceofflushinghives": "RegPerfOpHiveFlushWroteLogFile",
}


if __name__ == "__main__":

      # Operation-End 등 상관없는 TaskName등 다 handling 할것


   def get_splunkd_and_descendent_pids( es_index__all_log_entries : list,
                                        include_splunkd = False, # or also 'conhost'??
                                        include_conhost = False, # 'conhost' which is child-process of splunkd,
                                                                 # should be the 
                                       ) -> dict:


            # SHOULD I KEEP 

            # JY @ 2023-10-25 : Get events that are descendent of "splunkd"
            #                   Need to write code that first figures out the
            #                   dependencies (root == splunkd process and process-tree)
            #     First write a loop for identifying that.


            splunkd_and_descendent_pids = dict()
            first_splunkd_entry_found = False
            splunkd_pid = None

            for i, log_entry in enumerate(es_index__all_log_entries):
               logentry_TaskName = log_entry.get('_source_EventName')
               logentry_timestamp = log_entry.get('_source_@timestamp')
               logentry_ProcessID = log_entry.get('_source_ProcessID')
               logentry_ThreadID = log_entry.get('_source_ThreadID')
               logentry_ProcessName = log_entry.get('_source_ProcessName')
               logentry_ProviderName = log_entry.get('_source_ProviderName')
               logentry_ProviderGuid = log_entry.get('_source_ProviderGuid')

               # ==============================================================================================
               # 1. Get the PID of "splunkd.exe"
               #    Could utilize the 'json' file in "caldera/etw/tmp", 
               #    but there wre incidents where it is incorrect.
               #    So just capture the first entry with ProcessName of "splunkd"
               #    and get the PID

               if ("splunkd" in logentry_ProcessName) and (first_splunkd_entry_found == False):
                  splunkd_and_descendent_pids[logentry_ProcessID] = {"ProcessName": logentry_ProcessName,
                                                                     "ParentProcessID" : "no-need-to-collect",
                                                                     "FormattedMessage": "no-need-to-collect"}
                  first_splunkd_entry_found = True
                  splunkd_pid = logentry_ProcessID
               # ==============================================================================================

               # 2. Record the descendent processes of splunkd
               if ("ProcessStart" in logentry_TaskName) and (first_splunkd_entry_found == True):
                  

                  ProcessStart_Event_ParentProcessID = int(log_entry.get('_source_XmlEventData_ParentProcessID').replace( "," , "" ))
                  ProcessStart_Event_ChildProcessID = int(log_entry.get('_source_XmlEventData_ProcessID').replace( "," , "" ))
                  ProcessStart_Event_FormattedMessage = log_entry.get('_source_XmlEventData_FormattedMessage') 
                  if ProcessStart_Event_ParentProcessID in splunkd_and_descendent_pids:
                     splunkd_and_descendent_pids[ ProcessStart_Event_ChildProcessID ] = {"ProcessName": "N/A",
                                                                                       "ParentProcessID" : ProcessStart_Event_ParentProcessID,
                                                                                       "FormattedMessage": ProcessStart_Event_FormattedMessage}
               # ==============================================================================================
               # 3. Try to get the ProcessName of descendent-processes of splunkd 
               #    (empirically, could get 'conhost' but others hard to get -- values are N/A )

               if (logentry_ProcessID in splunkd_and_descendent_pids) and (splunkd_and_descendent_pids[logentry_ProcessID]["ProcessName"] == "N/A"):
                  splunkd_and_descendent_pids[logentry_ProcessID]["ProcessName"] = logentry_ProcessName
            
            
            if include_splunkd == False:
               removed_splunkd = splunkd_and_descendent_pids.pop(splunkd_pid)

            if include_conhost == False:
               # don't include conhost, the direct-child of splunkd
               for pid in splunkd_and_descendent_pids:
                  
                  if splunkd_and_descendent_pids[pid]['ProcessName'] == 'conhost' and \
                     splunkd_and_descendent_pids[pid]['ParentProcessID'] == splunkd_pid:
                     
                     conhost_pid = pid

               removed_conhost = splunkd_and_descendent_pids.pop(conhost_pid)
                     



            return splunkd_and_descendent_pids




   def get_log_entries_of_splunkd_and_descendent_pids( es_index__all_log_entries : list,
                                                          get_splunkd_and_descendent_pids : dict ) -> list:

            # JY @ 2023-10-25 : Get events that are descendent of "splunkd"
            #                   Need to write code that first figures out the
            #                   dependencies (root == splunkd process and process-tree)
            #     First write a loop for identifying that.

            splunkd_and_descentdents_log_entries = []

            for i, log_entry in enumerate(es_index__all_log_entries):
               logentry_ProcessID = log_entry.get('_source_ProcessID')
               logentry_TaskName = log_entry.get('_source_EventName')

               if logentry_ProcessID in get_splunkd_and_descendent_pids:
                  # ==============================================================================================
                  # tasknames to skip
                  # -- based on : /data/d1/jgwak1/tabby/STREAMLINED_DATA_GENERATION_MultiGraph/STEP_2_Benign_NON_TARGETTED_SUBGRAPH_GENERATION_GeneralLogCollection_subgraphs/model_v3_PW/FirstStep.py
                  if logentry_TaskName.lower() in ["operationend", "namedelete"]: 
                     continue
                  # ==============================================================================================


                  splunkd_and_descentdents_log_entries.append(log_entry)

               # JY @ 2023-10-28 : Drop events that correspond to OperationEnd?

            return splunkd_and_descentdents_log_entries



   def get_log_entries_with_entity_info( log_entries : list ) -> list:


      ''' JY @ 2023-11-1: 
               Should the entity be same as UID if we are to utilize CG for explanation?
      
      '''

      log_entries_with_entity_info = []

      # For following,
      # refer to: /data/d1/jgwak1/tabby/STREAMLINED_DATA_GENERATION_MultiGraph/STEP_2_Benign_NON_TARGETTED_SUBGRAPH_GENERATION_GeneralLogCollection_subgraphs/model_v3_PW/FirstStep.py
      fileobject_to_filename_mapping = dict()
      keyobject_to_relativename_mapping = dict()
      


      for log_entry in log_entries:


         logentry_ProviderGuid = log_entry.get('_source_ProviderGuid')
         logentry_TaskName = log_entry.get('_source_EventName')
         logentry_ProcessID = log_entry.get('_source_ProcessID')
         logentry_ThreadID = log_entry.get('_source_ThreadID')
         # logentry_XmlEventData = log_entry.get('_source', {}).get('XmlEventData')

         # log_entry['GENERAL_ENTITY'] = f"{logentry_ProcessID}__{logentry_ThreadID}" # this doesn't really make sense 
                                                                                      # to use within sequence

         if logentry_TaskName.lower() in ["operationend", "namedelete"]: 
            continue


         #=============================================================================================================
         if logentry_ProviderGuid == FILE_PROVIDER.lower():
            # Entity associated with a File-Event?
            # --> Probably the 'File'            
            # ----> 'FileName' or 'FileObject', etc. depending on Event (need to resolve 'mapping')
            # ----> also, keep track of process & thread that carried out the file-event
            



            logentry_FileName = log_entry.get('_source_XmlEventData_FileName') 
            logentry_FileObject = log_entry.get('_source_XmlEventData_FileObject')


            if logentry_TaskName.lower() in {"create", "createnewfile"}:
               # JY: 'create' and 'createnewfile' provides both 'logentry_FileObject' and 'logentry_FileName'
               fileobject_to_filename_mapping[logentry_FileObject] = str(logentry_FileName)
               log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_FileObject}__{str(logentry_FileName)}"


            elif logentry_TaskName.lower() in {"close"}:
               # JY: "close" appear to provide only 'logentry_FileObject'
               logentry_FileName = fileobject_to_filename_mapping.get(logentry_FileObject, "None")
               log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_FileObject}__{logentry_FileName}"

            else: # all other tasknames
               # JY: ALL OTHER Opcodes appear to provide only 'logentry_FileObject'
               logentry_FileName = fileobject_to_filename_mapping.get(logentry_FileObject, "None")
               log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_FileObject}__{logentry_FileName}"



         #=============================================================================================================
         if logentry_ProviderGuid == REGISTRY_PROVIDER.lower():
            # Entity associated with a Registry-Event?
            # --> Probably the 'Registry-Key'            
            # ----> 'RelativeName' or 'KeyObject', etc. depending on Event (need to resolve 'mapping')
            # ----> also, keep track of process & thread that carried out the file-event


            logentry_OpcodeName = log_entry.get('_source_OpcodeName')
            logentry_KeyObject = log_entry.get('_source_XmlEventData_KeyObject')
            logentry_RelativeName = log_entry.get('_source_XmlEventData_RelativeName')

            logentry_KeyName = log_entry.get('_source_XmlEventData_KeyName') # ?


            #if logentry_TaskName in {'EventID(1)','EventID(2)'}:---> option 1
            if logentry_OpcodeName in {"CreatKey","OpenKey"}: #-----> option2 
               # JY: 'CreateKey' and 'OpenKey' provides both 'logentry_KeyObject' and 'logentry_RelativeName'

               keyobject_to_relativename_mapping[logentry_KeyObject] = str(logentry_RelativeName)

               log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_KeyObject}__{str(logentry_RelativeName)}"  # add to entity

            #elif logentry_TaskName == 'EventID(13)' --->option1 
            elif logentry_OpcodeName == "CloseKey": #--->option2

               # JY: "CloseKey" appear to provide only 'logentry_KeyObject'

               logentry_RelativeName = keyobject_to_relativename_mapping.get(logentry_KeyObject, "None")

               log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_KeyObject}__{logentry_RelativeName}"

            else: # ALL OTHER Opcodes  
               # JY: ALL OTHER Opcodes appear to provide only 'logentry_KeyObject'

               logentry_RelativeName = keyobject_to_relativename_mapping.get(logentry_KeyObject, "None")

               log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_KeyObject}__{logentry_RelativeName}"

         #=============================================================================================================

         if logentry_ProviderGuid == NETWORK_PROVIDER.lower():
            # Entity associated with a Network-Event?
            # --> Probably the 'IP-address' that 'this-machine' communicated with            
            # ----> 'daddr' depending on Event 
            # ----> also, keep track of process & thread that carried out the file-event

            logentry_destaddr = log_entry.get('_source_XmlEventData_daddr') 

            log_entry['PROVIDER_SPECIFIC_ENTITY'] = f"{logentry_destaddr}"


         #=============================================================================================================

         if logentry_ProviderGuid == PROCESS_PROVIDER.lower():
            # Entity associated with a Process-Event?
            # --> Process and Thread that took action.

            log_entry['PROVIDER_SPECIFIC_ENTITY'] = "None"

            # Perhaps imagename? -- I think this mostly happens when imageload-and-unload events -- so don't use it.
            # logentry_ImageName = log_entry.get('_source_XmlEventData_ImageName', 'None')

            # if logentry_ImageName != "None":
            #    print()
            pass

         #=============================================================================================================
         log_entries_with_entity_info.append(log_entry)


      

      # [ f"{x['_source_EventName']}__{x['PROVIDER_SPECIFIC_ENTITY']}" for x in log_entries_with_entity_info ] 

      # [ {"ProcessID": x['_source_ProcessID'],
      #    "ThreadID": x['_source_ThreadID'],
      #    "TaskName": x['_source_EventName'],
      #    "logentry_OpcodeName": x['_source_OpcodeName'],
      #    "PROVIDER_SPECIFIC_ENTITY": x['PROVIDER_SPECIFIC_ENTITY']} 
      # for x in log_entries_with_entity_info ] 
         
         # x['_source_EventName']}__{x['PROVIDER_SPECIFIC_ENTITY']}" for x in log_entries_with_entity_info ] 

      return log_entries_with_entity_info






   print()

   # 1.
   # For each Powershell-Dataset (Both Benign and Malware), 
   # get event-sequences with statistically significant frequencies using GSP alogrihtm,
   # and make it into a dictionary (key: dataset-name, value: sorted-list-of-event-sequences-by-significance) 
   # and save it to a json file

   query_body = { "query": {  "match_all": {} }, "sort" : [ { "TimeStamp" : { "order" : "asc" } } ] }




   all_dataset_indices = \
      [

         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_22_51.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_22_59.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_23_03.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_23_05.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_23_09.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_23_21.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_27.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_29.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_32.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_34.yml",

         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_36.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_41.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_44.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_09.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_12.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_17.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_19.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_33.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_35.yml",
         "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_38.yml",
         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_25_56.yml",

         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_25_58.yml",
         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_26_00.yml",
         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_26_06.yml",
         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_26_08.yml",
         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_26_11.yml",
         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_26_14.yml",
         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_26_37.yml",
         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_26_39.yml",
         # "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_26_44.yml",  // no splunkd
         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_26_46.yml",
         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_26_49.yml",

         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_27_28.yml",
         "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_27_37.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_08.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_11.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_13.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_15.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_17.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_21.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_24.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_26.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_30.yml",

         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_32.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_34.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_36.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_38.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_41.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_43.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_45.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_47.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_49.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_51.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_55.yml",

         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_02.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_04.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_09.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_11.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_13.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_15.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_18.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_51.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_54.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_56.yml",

         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_59.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_12_01.yml",
         "custom_adversary_profile__None__None__stockpile__2023-10-25-21_12_14.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_01.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_06.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_08.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_11.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_13.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_19.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_22.yml",

         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_24.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_26.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_31.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_58.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_03.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_07.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_11.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_16.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_18.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_23.yml",

         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_25.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_28.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_30.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_33.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_35.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_39.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_42.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_46.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_49.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_51.yml",

         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_54.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_57.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_22_00.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_22_03.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_22_07.yml",
         "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_22_10.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_51_46.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_51_48.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_51_51.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_52_00.yml",

         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_52_02.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_52_05.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_52_13.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_52_16.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_52_22.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_52_27.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_52_34.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_52_36.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_52_41.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_52_48.yml",

         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_52_53.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_53_00.yml",
         "custom_adversary_profile__none__survey_paper_apt_attack_six_phases__both__2023-10-30-17_53_04.yml",

      ]
   all_dataset_indices = [x.removesuffix(".yml") for x in all_dataset_indices]

   # RequestError(400, 'illegal_argument_exception', 'ReleasableBytesStreamOutput cannot hold more than 2GB of data')
   # elasticsearch.exceptions.RequestError: RequestError(400, 'illegal_argument_exception', 'ReleasableBytesStreamOutput cannot hold more than 2GB of data')
   # https://discuss.elastic.co/t/cluster-state-yellow-2-shards-initializing-with-multiple-failed-attempts-illegalargumentexception-releasablebytesstreamoutput-cannot-hold-more-than-2gb-of-data/334008/2


   skip_indices = []
   skipped_indices = []




   #######################################################################################################################
   
   index_2_sorted__log_entries_of_interest = dict()
   index_2_sorted__log_entries_of_interest__key_attrs_with_entity = dict()

   m = 0
   for es_index in all_dataset_indices:

         get_entries_start_time = datetime.datetime.now()
         print(f"Getting-entries - Start Time: {get_entries_start_time}", flush=True)

         if es_index in skip_indices:
            print(f"skipping {es_index}, as it is too big", flush=True)
            continue
         es_index = es_index.lower() # all elastic-search indices are lower-cased.
         try:
               # Read in all log entries of current es-index.
               es = Elasticsearch(['http://ocelot.cs.binghamton.edu:9200'],timeout = 300)   
               es.indices.put_settings(index = es_index, body={'index':{'max_result_window':99999999}})
               result = es.search(index = es_index, 
                                 size = 99999999)
         except:
            skipped_indices.append(es_index)
            print(f"\n{len(skipped_indices)}:  {es_index}  is skipped as Elasticsearch doesn't contain it\n", flush = True)
            continue

         es_index__all_log_entries = result['hits']['hits']    # list of dicts

         # JY : /data/d1/jgwak1/tabby/STREAMLINED_DATA_GENERATION_MultiGraph/STEP_2_Benign_NON_TARGETTED_SUBGRAPH_GENERATION_GeneralLogCollection_subgraphs/model_v3_PW/FirstStep.py
         flattened__es_index__all_log_entries = flatten_all_hits( es_index__all_log_entries ) 


         m = m+1
         print(f"{m}/{len(all_dataset_indices)}. -- es_index: {es_index}", flush= True)


         try:
            flattened__es_index__all_log_entries__with_entity_info = get_log_entries_with_entity_info( flattened__es_index__all_log_entries )
         except:
            continue

         try:
            splunkd_descendent_pids_dict = get_splunkd_and_descendent_pids( flattened__es_index__all_log_entries__with_entity_info,
                                                                              include_splunkd = False ) # drop splunkd
         except:
            continue

         try:
            splunkd_and_descendents_log_entries = get_log_entries_of_splunkd_and_descendent_pids( flattened__es_index__all_log_entries__with_entity_info,
                                                                                                   splunkd_descendent_pids_dict )
         except:
            continue

         # JY @ 2023-11-01



         print(f"len(splunkd_and_descendents_log_entries): {len(splunkd_and_descendents_log_entries)}", flush = True )

         if len(splunkd_and_descendents_log_entries) == 0:
            raise Exception(f"len(es_index) == 0")
         # index_2_sorted__log_entries_of_interest[ es_index ] = splunkd_and_descendents_log_entries

         index_2_sorted__log_entries_of_interest__key_attrs_with_entity[es_index] = \
         [ {
            "ProcessID": x['_source_ProcessID'],
            "ThreadID": x['_source_ThreadID'],
            "TaskName": x['_source_EventName'],
            "logentry_OpcodeName": x['_source_OpcodeName'],
            "ProviderGuid": x['_source_ProviderGuid'],
            "PROVIDER_SPECIFIC_ENTITY": x['PROVIDER_SPECIFIC_ENTITY'],
            } 
         for x in splunkd_and_descendents_log_entries ] 



         # mem
         del es_index__all_log_entries
         del flattened__es_index__all_log_entries
         del flattened__es_index__all_log_entries__with_entity_info
         del splunkd_descendent_pids_dict
         del splunkd_and_descendents_log_entries
         gc.collect()


         get_entries_end_time = datetime.datetime.now() ; print(f"Getting-entries - End Time: {get_entries_end_time}", flush=True)
         get_entries_elapsed_time = get_entries_end_time - get_entries_start_time ; print(f"Getting-entries - Elapsed Time: {get_entries_elapsed_time}", flush=True)

   #--------------------------------------------------------------------------------------------------------------------------
   # Extract only the EventNames from the log entries

   # index_2_sorted__log_entries_of_interest__only_EventNames = dict()

   ######################################################################
   # JY @ 2023-11-02 maybe could inject this part into above for-loop to save some memory?

   # index_2_sorted__log_entries_of_interest__key_attrs_with_entity = dict()

   # for index in index_2_sorted__log_entries_of_interest:

   #    # index_2_sorted__log_entries_of_interest__only_EventNames[index] = \
   #    #    [ x['_source']['EventName'] for x in index_2_sorted__log_entries_of_interest[index] ]

   #    index_2_sorted__log_entries_of_interest__key_attrs_with_entity[index] = \
   #    [ {
   #       "ProcessID": x['_source_ProcessID'],
   #       "ThreadID": x['_source_ThreadID'],
   #       "TaskName": x['_source_EventName'],
   #       "logentry_OpcodeName": x['_source_OpcodeName'],
   #       "ProviderGuid": x['_source_ProviderGuid'],
   #       "PROVIDER_SPECIFIC_ENTITY": x['PROVIDER_SPECIFIC_ENTITY'],
   #       } 
   #    for x in index_2_sorted__log_entries_of_interest[index] ] 


   # index_2_sorted__log_entries_of_interest__key_attrs_with_entity__count = {k:len(v) for k,v in index_2_sorted__log_entries_of_interest__key_attrs_with_entity.items()}


   #--------------------------------------------------------------------------------------------------------------------------
   # JY @ TODO for 2023-11-2 
   #     Now here find if there are intersecting entities across samples
   #      Not all may intersect across all indices obviously, 
   #      but still if some exist, could do it -- think more
   #     set-operations

   # get a set of PROVIDER_SPECIFIC_ENTITY for each index 
   
   # JY: identify which ones process result in log-stash , m
   #     perhaps the conhost one? 
   index_entity_set_dict = dict()
   for index in index_2_sorted__log_entries_of_interest__key_attrs_with_entity:
      
      index_entity_set_dict[index] = \
         { x['PROVIDER_SPECIFIC_ENTITY'] for x in \
            index_2_sorted__log_entries_of_interest__key_attrs_with_entity[index] }


   # JY: 
   #     Identify: 
   #      (1) Entities that intersect-across-all-indices 
   #      (2) Entities that don't intersect across any indices (i.e. elements unique to each set)
   #      (3) Entities that intersect but not all 
   #          -- might be great to sort by number-of-intersections & information of indices 

   list_of_entity_sets = [ v for k,v in index_entity_set_dict.items() ]


   # (1) Entities that intersect-across-all-indices --------------
   entities__intersecting_across_all_indices = set.intersection( *list_of_entity_sets )

   # (2) Entities that don't intersect across any indices (i.e. elements unique to each set) --------------
   entities__unique_to_an_index = dict()

   for curr_index, curr_entity_set in index_entity_set_dict.items():

      other_sets = [ entity_set for index, entity_set in index_entity_set_dict.items() \
                     if index != curr_index ]
      unique_to_curr_set = curr_entity_set.difference(*other_sets)
      entities__unique_to_an_index[ curr_index ] = unique_to_curr_set
   
      # # following for veritifaction
      # entity_to_check = '0xffff8306dac94220__\\Device\\HarddiskVolume2\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules\\BitLocker\\'         
      # [ [k, (entity_to_check in v) ] for k,v in index_entity_set_dict.items() ] 
      

   # (3) Entities that intersect but not all --------------
   #     -- might be great to sort by number-of-intersections & information of indices 

   all_entities = set.union(*[ v for k,v in index_entity_set_dict.items() ])
   
   # first get rid of entities that are unique to 1 index or intersect across all indices
   entities__intersecting_but_not_all = all_entities\
                                          - set().union( *entities__unique_to_an_index.values() )\
                                          -  entities__intersecting_across_all_indices
   
   entities__intersecting_but_not_all__index_map = dict()
   for curr_entity in entities__intersecting_but_not_all:
      corresponding_indices = [ index for index, entity_set in index_entity_set_dict.items() \
                                 if curr_entity in entity_set ]
      entities__intersecting_but_not_all__index_map[ curr_entity ] = {"# intersecting_indices": len(corresponding_indices),
                                                                        "indices": corresponding_indices }
   # sort in descending order by '# intersecting_indices'
   entities__intersecting_but_not_all__index_map = dict(sorted(entities__intersecting_but_not_all__index_map.items(), 
                                                               key=lambda item: item[1]['# intersecting_indices'], reverse=True))

   # JY: json 으로 저장해라


   with open('entities__intersecting_across_all_indices.json', 'w') as json_file:
      json.dump(list(entities__intersecting_across_all_indices), json_file)

   with open('entities__unique_to_an_index.json', 'w') as json_file:
      json.dump({k:list(v) for k,v in entities__unique_to_an_index.items()}, json_file)

   with open('entities__intersecting_but_not_all__index_map.json', 'w') as json_file:
      json.dump( entities__intersecting_but_not_all__index_map, json_file)    


   with open('entities__intersecting_but_not_all__index_map__only_#intersecting_indices.json', 'w') as json_file:
      json.dump( {k:v['# intersecting_indices'] for k,v in entities__intersecting_but_not_all__index_map.items()}, json_file)    








   #--------------------------------------------------------------------------------------------------------------------------
   #--------------------------------------------------------------------------------------------------------------------------
   #--------------------------------------------------------------------------------------------------------------------------
   #--------------------------------------------------------------------------------------------------------------------------
   #--------------------------------------------------------------------------------------------------------------------------
   
   # JY: SPM can be done independently from getting intersectng paterns



   # #######################################################################################################################
   # # Divide based on super-batch

   # super_batch_size = 10 # 10 seems manageable with 256GB

   # if len(all_dataset_indices) % super_batch_size == 1:
   #    raise RuntimeError("remainder can't be 1 to perform SPM", flush = True)

   # random.shuffle(all_dataset_indices) # following their logic ; in-place
   # all_dataset_indices__sublists = [all_dataset_indices[i:i+super_batch_size] for i in range(0, len(all_dataset_indices), super_batch_size)] 

   # #----------------------------------------------------------------------------------------------------------------------
   
   # parent_dir = "/data/d1/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Task_1__Behavior_identification_and_intention_learning/1_1__Sequential_pattern_mining/"
   # super_batch_pickle_files_save_dirpath = os.path.join(parent_dir, 
   #                                        f"super_batch_spm_result_pickles_dir__{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
   # if not os.path.exists(super_batch_pickle_files_save_dirpath):
   #    os.makedirs(super_batch_pickle_files_save_dirpath)
   # else:
   #    raise RuntimeError(f"path already exists: {super_batch_pickle_files_save_dirpath}", flush = True)


   skip_following = True
   
   if skip_following:
      exit

   # Apply SPM (or CSPM) Algorithm
   sequence_DB = [ v for k,v in index_2_sorted__log_entries_of_interest__only_EventNames.items() ]

   del index_2_sorted__log_entries_of_interest
   # del index_2_sorted__log_entries_of_interest__only_EventNames_count
   # del index_2_sorted__log_entries_of_interest__key_attrs_with_entity__count


   # JY: Takes very log time. 
   #     Very computatinally expensive with so many events.   
   start_time = datetime.datetime.now()
   print(f"Seq2Pat start time: {start_time}", flush=True)  
   ''' https://github.com/fidelity/seq2pat/blob/1b27c79af4c5d33c8714b9f010dd8ea4efd26d50/sequential/seq2pat.py#L297 '''

   max_span = 10 # maybe 10 is too big?
   batch_size = super_batch_size // 3
   discount_factor = 0.2
   n_jobs = -1 

   seq2pat = Seq2Pat(sequences= sequence_DB,
                     max_span = max_span, # default
                     batch_size = batch_size,   # default
                     discount_factor = discount_factor,  # default
                     n_jobs = n_jobs, #  If -1 all CPUs are used. If -2, all CPUs but one are used.
                     )
   print(f"\n#sequence_DB: {len(sequence_DB)}\n", flush = True)
   print(f"\nmax_span (default 10): {max_span}", flush = True)
   print(f"batch_size (default None): {batch_size}", flush = True)
   print(f"discount_factor (default 0.2): {discount_factor}", flush = True)
   print(f"n_jobs (default 2): {n_jobs}\n", flush = True)

   # According to the paper, can use ratio (floating points)
   # > Similary, while this examples uses an integer value for the frequency threshold, it is possible to use a floating point number
   #   to specify an occurence percentage in the size of the sequence database.



   # #            If int, represents the minimum number of sequences (rows) a pattern should occur.
   #            If float, should be (0.0, 1.0] and represents
   sub_min_frequency = 1
   print(f"\nsub_min_frequency: {sub_min_frequency}\n", flush = True)

   super_batch__patterns = seq2pat.get_patterns(min_frequency=sub_min_frequency)      
   # print(patterns, flush=True)
   end_time = datetime.datetime.now()
   print(f"Seq2Pat end time: {end_time}", flush=True)
   elapsed_time = end_time - start_time
   print(f"Seq2Pat elapsed_time: {elapsed_time}", flush=True)
   
   # -------------------------------------------------------------------------------------------------------------
   with open( os.path.join( super_batch_pickle_files_save_dirpath,
                           f"super_batch__{super_batch_idx}.pickle"), "wb" ) as f:
      pickle.dump( super_batch__patterns , f )

   print(f"\nDumped to {os.path.join( super_batch_pickle_files_save_dirpath, f'super_batch__{super_batch_idx}.pickle')}\n",
      flush = True)

   memory_percent = psutil.virtual_memory().percent
   print(f"Memory usage: {memory_percent}%", flush = True)          

   del super_batch__patterns
   del sequence_DB
   del seq2pat
   gc.collect()





