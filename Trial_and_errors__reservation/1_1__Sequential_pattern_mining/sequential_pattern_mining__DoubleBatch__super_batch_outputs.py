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


FILE_PROVIDER = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
NETWORK_PROVIDER = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
PROCESS_PROVIDER = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
REGISTRY_PROVIDER = "{70EB4F03-C1DE-4F73-A051-33D13D5413BD}"




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


   def get_splunkd_and_descendent_pids( es_index__all_log_entries : list ) -> dict:

            # JY @ 2023-10-25 : Get events that are descendent of "splunkd"
            #                   Need to write code that first figures out the
            #                   dependencies (root == splunkd process and process-tree)
            #     First write a loop for identifying that.


            splunkd_and_descendent_pids = dict()
            first_splunkd_entry_found = False

            for i, log_entry in enumerate(es_index__all_log_entries):
               logentry_TaskName = log_entry.get('_source', {}).get('EventName')
               logentry_timestamp = log_entry.get('_source', {}).get('@timestamp')
               logentry_ProcessID = log_entry.get('_source', {}).get('ProcessID')
               logentry_ThreadID = log_entry.get('_source', {}).get('ThreadID')
               logentry_ProcessName = log_entry.get('_source', {}).get('ProcessName')
               logentry_ProviderName = log_entry.get('_source', {}).get('ProviderName')
               logentry_ProviderGuid = log_entry.get('_source', {}).get('ProviderGuid')
               logentry_XmlEventData = log_entry.get('_source', {}).get('XmlEventData')

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
               # ==============================================================================================

               # 2. Record the descendent processes of splunkd
               if ("ProcessStart" in logentry_TaskName) and (first_splunkd_entry_found == True):
                  
                  ProcessStart_Event_ParentProcessID = int(logentry_XmlEventData['ParentProcessID'].replace( "," , "" ))
                  ProcessStart_Event_ChildProcessID = int(logentry_XmlEventData['ProcessID'].replace( "," , "" ))
                  ProcessStart_Event_FormattedMessage = logentry_XmlEventData['FormattedMessage']

                  if ProcessStart_Event_ParentProcessID in splunkd_and_descendent_pids:
                     splunkd_and_descendent_pids[ ProcessStart_Event_ChildProcessID ] = {"ProcessName": "N/A",
                                                                                       "ParentProcessID" : ProcessStart_Event_ParentProcessID,
                                                                                       "FormattedMessage": ProcessStart_Event_FormattedMessage}
               # ==============================================================================================
               # 3. Try to get the ProcessName of descendent-processes of splunkd 
               #    (empirically, could get 'conhost' but others hard to get -- values are N/A )

               if (logentry_ProcessID in splunkd_and_descendent_pids) and (splunkd_and_descendent_pids[logentry_ProcessID]["ProcessName"] == "N/A"):
                  splunkd_and_descendent_pids[logentry_ProcessID]["ProcessName"] = logentry_ProcessName
            
            
            return splunkd_and_descendent_pids




   def get_log_entries_of_splunkd_and_descendent_pids( es_index__all_log_entries : list,
                                                          get_splunkd_and_descendent_pids : dict ) -> list:

            # JY @ 2023-10-25 : Get events that are descendent of "splunkd"
            #                   Need to write code that first figures out the
            #                   dependencies (root == splunkd process and process-tree)
            #     First write a loop for identifying that.

            splunkd_and_descentdents_log_entries = []

            for i, log_entry in enumerate(es_index__all_log_entries):
               logentry_ProcessID = log_entry.get('_source', {}).get('ProcessID')
               logentry_TaskName = log_entry.get('_source', {}).get('EventName')

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




   print()

   # 1.
   # For each Powershell-Dataset (Both Benign and Malware), 
   # get event-sequences with statistically significant frequencies using GSP alogrihtm,
   # and make it into a dictionary (key: dataset-name, value: sorted-list-of-event-sequences-by-significance) 
   # and save it to a json file

   query_body = { "query": {  "match_all": {} }, "sort" : [ { "TimeStamp" : { "order" : "asc" } } ] }




   all_dataset_indices = \
      [     "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_22_51",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_22_55",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_22_59",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_23_03",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_23_05",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_23_09",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-25-21_23_21",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_27",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_29",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_32",

            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_34",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_36",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_41",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_2__both__2023-10-25-21_23_44",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_09",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_12",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_17",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_19",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_33",
            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_35",

            "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_3__both__2023-10-25-21_24_38",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_25_56",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_25_58",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_26_00",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_26_06",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_26_08",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_26_11",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_1__both__2023-10-25-21_26_14",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_26_37",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_26_39",

            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_26_44",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_26_46",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_26_49",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_27_28",
            "custom_adversary_profile__APT_3__APT3_Phase3_Pattern_2__both__2023-10-25-21_27_37",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_08",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_11",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_13",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_15",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_17",

            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_21",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_24",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_26",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_30",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_32",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_34",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_36",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_38",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_41",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_43",

            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_45",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_47",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_49",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_51",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_55",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_00",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_02",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_04",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_09",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_11",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_13",

            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_15",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_18",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_51",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_54",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_56",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_11_59",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_12_01",
            "custom_adversary_profile__None__None__stockpile__2023-10-25-21_12_14",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_01",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_06",

            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_08",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_11",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_13",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_19",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_22",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_24",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_26",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_31",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_20_58",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_03",
            
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_07",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_11",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_16",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_18",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_23",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_25",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_28",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_30",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_33",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_35",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_39",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_42",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_46",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_49",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_51",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_54",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_21_57",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_22_00",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_22_03",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_22_07",
            "custom_adversary_profile__None__Survey_Paper_APT_Attack_Six_Phases__both__2023-10-25-21_22_10",
      ]

   # RequestError(400, 'illegal_argument_exception', 'ReleasableBytesStreamOutput cannot hold more than 2GB of data')
   # elasticsearch.exceptions.RequestError: RequestError(400, 'illegal_argument_exception', 'ReleasableBytesStreamOutput cannot hold more than 2GB of data')
   # https://discuss.elastic.co/t/cluster-state-yellow-2-shards-initializing-with-multiple-failed-attempts-illegalargumentexception-releasablebytesstreamoutput-cannot-hold-more-than-2gb-of-data/334008/2


   skip_indices = []
   skipped_indices = []


   #######################################################################################################################
   # Divide based on super-batch

   super_batch_size = 10 # 10 seems manageable with 256GB

   if len(all_dataset_indices) % super_batch_size == 1:
      raise RuntimeError("remainder can't be 1 to perform SPM", flush = True)

   random.shuffle(all_dataset_indices) # following their logic ; in-place
   all_dataset_indices__sublists = [all_dataset_indices[i:i+super_batch_size] for i in range(0, len(all_dataset_indices), super_batch_size)] 

   #----------------------------------------------------------------------------------------------------------------------
   
   parent_dir = "/data/d1/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Task_1__Behavior_identification_and_intention_learning/1_1__Sequential_pattern_mining/"
   super_batch_pickle_files_save_dirpath = os.path.join(parent_dir, 
                                          f"super_batch_spm_result_pickles_dir__{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
   if not os.path.exists(super_batch_pickle_files_save_dirpath):
      os.makedirs(super_batch_pickle_files_save_dirpath)
   else:
      raise RuntimeError(f"path already exists: {super_batch_pickle_files_save_dirpath}", flush = True)

   #######################################################################################################################
   

   for super_batch_idx, dataset_indices_sublist in enumerate(all_dataset_indices__sublists):


         index_2_sorted__log_entries_of_interest = dict()

         get_entries_start_time = datetime.datetime.now()
         print(f"Getting-entries - Start Time: {get_entries_start_time}", flush=True)
         m = 0
         for es_index in dataset_indices_sublist:
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
                  es_index__all_log_entries = result['hits']['hits']    # list of dicts
                  m = m+1
                  print(f"{m}/{len(all_dataset_indices)}. -- es_index: {es_index}", flush= True)

                  splunkd_and_descendent_pids_dict = get_splunkd_and_descendent_pids( es_index__all_log_entries )
                  splunkd_and_descendents_log_entries = get_log_entries_of_splunkd_and_descendent_pids( es_index__all_log_entries,
                                                                                                      splunkd_and_descendent_pids_dict )
                  print(f"len(splunkd_and_descendents_log_entries): {len(splunkd_and_descendents_log_entries)}", flush = True )

                  if len(splunkd_and_descendents_log_entries) == 0:
                     raise Exception(f"len(es_index) == 0")
                  index_2_sorted__log_entries_of_interest[ es_index ] = splunkd_and_descendents_log_entries
            except:
               skipped_indices.append(es_index)
               print(f"\n{len(skipped_indices)}:  {es_index}  is skipped as Elasticsearch doesn't contain it\n", flush = True)
         get_entries_end_time = datetime.datetime.now() ; print(f"Getting-entries - End Time: {get_entries_end_time}", flush=True)
         get_entries_elapsed_time = get_entries_end_time - get_entries_start_time ; print(f"Getting-entries - Elapsed Time: {get_entries_elapsed_time}", flush=True)

         #--------------------------------------------------------------------------------------------------------------------------
         # Extract only the EventNames from the log entries

         index_2_sorted__log_entries_of_interest__only_EventNames = dict()
         for index in index_2_sorted__log_entries_of_interest:
            index_2_sorted__log_entries_of_interest__only_EventNames[index] = [ x['_source']['EventName'] for x in index_2_sorted__log_entries_of_interest[index] ]

         index_2_sorted__log_entries_of_interest__only_EventNames_count = {k:len(v) for k,v in index_2_sorted__log_entries_of_interest__only_EventNames.items()}

         #--------------------------------------------------------------------------------------------------------------------------
         # Apply SPM (or CSPM) Algorithm
         sequence_DB = [ v for k,v in index_2_sorted__log_entries_of_interest__only_EventNames.items() ]

         del index_2_sorted__log_entries_of_interest
         del index_2_sorted__log_entries_of_interest__only_EventNames_count

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





