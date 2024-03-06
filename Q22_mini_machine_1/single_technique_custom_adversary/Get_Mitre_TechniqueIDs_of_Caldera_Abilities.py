import random
import pickle

# Added by JY
from pathlib import Path
import os



# JY @ 2023-10-12:
# 

import random
import pickle




# Added by JY
from pathlib import Path
import os
import yaml
import json

##########################################################################################################################
# JY: Updated @ 2023-10-22 based on updated-ver of Caldera


STOCKPILE_ABILITIES_DIRPATH = "/home/priti/Desktop/caldera/plugins/stockpile/data/abilities"
ATOMIC_ABILITIES_DIRPATH = "/home/priti/Desktop/caldera/plugins/atomic/data/abilities"

# Stockpile Abilities (#158 ; Note that not all supports Windows-Powershell) -- updated caldera-ver
stockpile_collection__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "collection") #------------------ #16
stockpile_command_and_control__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "command-and-control") #------------------ #3
stockpile_credential_access__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "credential-access") #------------------ #10
stockpile_defense_evasion__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "defense-evasion") #------------------ #15
stockpile_discovery__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "discovery") #------------------ #67
stockpile_execution__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "execution") #------------------ #9
stockpile_exfiltration__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "exfiltration") #------------------ #13
stockpile_impact__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "impact") #------------------ #8
stockpile_lateral_movement__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "lateral-movement") #------------------ #10
stockpile_persistence__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "persistence") #------------------ #1
stockpile_privilege_escalation__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "privilege-escalation") #------------------ #6

# Atomic Abilities (#1355; Note that not all supports Windows-Powershell)
atomic_collection__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "collection") #------------------ #44	
atomic_command_and_control__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "command-and-control") #------------------ #66
atomic_credential_access__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "credential-access") #------------------ #145
atomic_defense_evasion__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "defense-evasion") #------------------ #410
atomic_discovery__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "discovery") #------------------ #220
atomic_execution__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "execution") #------------------ #91
atomic_exfiltration__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "exfiltration") #------------------ #16
atomic_impact__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "impact") #------------------ #46
atomic_initial_access__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "initial-access") #------------------ #3
atomic_lateral_movement__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "lateral-movement") #------------------ #16
atomic_multiple__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "multiple") #------------------ #249
atomic_persistence__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "persistence") #------------------ #46
atomic_privilege_escalation__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "privilege-escalation") #------------------ #2
atomic_reconnaissance__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "reconnaissance") #------------------ #1



''' Get all mappings from abilities to their tactics and techniques (for stockpile and atomic abilities). '''

def remove_suffix(input_string, suffix):
    ''' string .removesuffix is supported from python3.9+. '''
    if input_string.endswith(suffix):
        return input_string[:-len(suffix)]
    return input_string



# Privilege Escalation
stockpile_privilege_escalation__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_privilege_escalation__dpath)]
atomic_privilege_escalation__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_privilege_escalation__dpath)]
privilege_escalation__abilitiy_ids = stockpile_privilege_escalation__ability_ids + atomic_privilege_escalation__ability_ids

# Credential Access
stockpile_credential_access__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_credential_access__dpath)]
atomic_credential_access__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_credential_access__dpath)]
credential_access__ability_ids = stockpile_credential_access__ability_ids + atomic_credential_access__ability_ids

# Discovery 
stockpile_discovery__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_discovery__dpath)]
atomic_discovery__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_discovery__dpath)]
discovery__ability_ids = stockpile_discovery__ability_ids + atomic_discovery__ability_ids

# Collection
stockpile_collection__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_collection__dpath)]
atomic_collection__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_collection__dpath)]
collection__ability_ids = stockpile_collection__ability_ids + atomic_collection__ability_ids

# Exfiltration
stockpile_exfiltration__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_exfiltration__dpath)]
atomic_exfiltration__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_exfiltration__dpath)]
exfiltration__ability_ids = stockpile_exfiltration__ability_ids + atomic_exfiltration__ability_ids

# Lateral Movement
stockpile_lateral_movement__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_lateral_movement__dpath)]
atomic_lateral_movement__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_lateral_movement__dpath)]
lateral_movement__ability_ids = stockpile_lateral_movement__ability_ids + atomic_lateral_movement__ability_ids

# Command and Control
stockpile_command_and_control__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_command_and_control__dpath)]
atomic_command_and_control__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_command_and_control__dpath)]
command_and_control__ability_ids = stockpile_command_and_control__ability_ids + atomic_command_and_control__ability_ids

# Defense Evasion
stockpile_defense_evasion__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_defense_evasion__dpath)]
atomic_defense_evasion__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_defense_evasion__dpath)]
defense_evasion__ability_ids = stockpile_defense_evasion__ability_ids + atomic_defense_evasion__ability_ids

# Execution
stockpile_execution__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_execution__dpath)]
atomic_execution__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_execution__dpath)]
execution__ability_ids = stockpile_execution__ability_ids + atomic_execution__ability_ids

# Impact
stockpile_impact__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_impact__dpath)]
atomic_impact__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_impact__dpath)]
impact__ability_ids = stockpile_impact__ability_ids + atomic_impact__ability_ids

# Persistence
stockpile_persistence__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_persistence__dpath)]
atomic_persistence__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_persistence__dpath)]
persistence__ability_ids = stockpile_persistence__ability_ids + atomic_persistence__ability_ids

# Initial Access
atomic_initial_access__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_initial_access__dpath)]

# Multiple
atomic_multiple__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_multiple__dpath)]

# Reconnaissance
atomic_reconnaissance__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_reconnaissance__dpath)]

##########################################################################################################################




def Get_All_Mitre_TechniqueIDs( write_fp ):
    

   # helper function for printing content in yaml file
   def yml_content_parse_helper( plugin_tactic__dpath, ability_id ):
            
        yml_fpath = os.path.join( plugin_tactic__dpath, f"{ability_id}.yml")
        with open(yml_fpath, 'r') as file:
            ability_yml = yaml.safe_load(file)
        if type(ability_yml) == list:
            ability_yml = ability_yml[0]
        

        try:
            ability_technique = ability_yml['technique']
        except:
            ability_technique = ability_yml['technique_id']

        try:
            ability_platforms = ability_yml['platforms']
        except:
            ability_platforms = ability_yml['executors'][0]['platform']


        ability_details__dict =\
             {
              "description": ability_yml['description'],
              "tactic": ability_yml['tactic'],
              "technique": ability_technique,
              "platforms": ability_platforms,
             }
        
        return ability_details__dict



   ab_list = pickle.load( open( os.path.join( str(Path(__file__).parent), 'ab_list__JY.pkl') ,'rb' ) )   # ab_list__JY

   global_dict = dict() # key -- caldera-bility-id / value -- 


   for ability in ab_list:

       
       ability_id = ability[0]
       
       # Privilege Escalation
       if ability_id in stockpile_privilege_escalation__ability_ids:
           ability_details__dict = yml_content_parse_helper( stockpile_privilege_escalation__dpath, ability_id )
           plugin= "stockpile"
       if ability_id in atomic_privilege_escalation__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_privilege_escalation__dpath, ability_id )
           plugin= "atomic"

       # Credential Access
       if ability_id in stockpile_credential_access__ability_ids:
           ability_details__dict = yml_content_parse_helper( stockpile_credential_access__dpath, ability_id )
           plugin= "stockpile"

       if ability_id in atomic_credential_access__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_credential_access__dpath, ability_id )
           plugin= "atomic"       

       # Discovery 
       if ability_id in stockpile_discovery__ability_ids:
           ability_details__dict = yml_content_parse_helper( stockpile_discovery__dpath, ability_id )
           plugin= "stockpile"

       if ability_id in atomic_discovery__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_discovery__dpath, ability_id )
           plugin= "atomic"

       # Collection
       if ability_id in stockpile_collection__ability_ids:
           ability_details__dict = yml_content_parse_helper( stockpile_collection__dpath, ability_id )
           plugin= "stockpile"

       if ability_id in atomic_collection__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_collection__dpath, ability_id )
           plugin= "atomic"
              
       # Exfiltration
       if ability_id in stockpile_exfiltration__ability_ids:
           ability_details__dict = yml_content_parse_helper( stockpile_exfiltration__dpath, ability_id )     
           plugin= "stockpile"

       if ability_id in atomic_exfiltration__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_exfiltration__dpath, ability_id )
           plugin= "atomic"


       # Lateral Movement
       if ability_id in stockpile_lateral_movement__ability_ids:
           ability_details__dict = yml_content_parse_helper( stockpile_lateral_movement__dpath, ability_id )
           plugin= "stockpile"

       if ability_id in atomic_lateral_movement__ability_ids:
           ability_details__dict =  yml_content_parse_helper( atomic_lateral_movement__dpath, ability_id )
           plugin= "atomic"

       # Command and Control
       if ability_id in stockpile_command_and_control__ability_ids:
           ability_details__dict = yml_content_parse_helper( stockpile_command_and_control__dpath, ability_id )
           plugin= "stockpile"

       if ability_id in atomic_command_and_control__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_command_and_control__dpath, ability_id )
           plugin= "atomic"

       # Defense Evasion
       if ability_id in stockpile_defense_evasion__ability_ids:
           ability_details__dict = yml_content_parse_helper( stockpile_defense_evasion__dpath, ability_id )
           plugin= "stockpile"
 
       if ability_id in atomic_defense_evasion__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_defense_evasion__dpath, ability_id )
           plugin= "atomic"

       # Execution
       if ability_id in stockpile_execution__ability_ids:
           ability_details__dict = yml_content_parse_helper( stockpile_execution__dpath, ability_id )
           plugin= "stockpile"

       if ability_id in atomic_execution__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_execution__dpath, ability_id )
           plugin= "atomic"

       # Impact
       if ability_id in stockpile_impact__ability_ids:
           ability_details__dict = yml_content_parse_helper( stockpile_impact__dpath, ability_id )
           plugin= "stockpile"

       if ability_id in atomic_impact__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_impact__dpath, ability_id )
           plugin= "atomic"

       # Persistence
       if ability_id in stockpile_persistence__ability_ids:
           ability_details__dict = yml_content_parse_helper( stockpile_persistence__dpath, ability_id )
           plugin= "stockpile"

       if ability_id in atomic_persistence__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_persistence__dpath, ability_id )
           plugin= "atomic"

       # Initial Access
       if ability_id in atomic_initial_access__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_initial_access__dpath, ability_id )
           plugin= "atomic"

       # Multiple
       if ability_id in atomic_multiple__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_multiple__dpath, ability_id )
           plugin= "atomic"

       # Reconnaissance
       if ability_id in atomic_reconnaissance__ability_ids:
           ability_details__dict = yml_content_parse_helper( atomic_reconnaissance__dpath, ability_id )
           plugin= "atomic"


       #    ability_details_dict_plus = ability_details__dict | {"id__dependence__fact": ability,
       #                                                         "plugin": plugin}
       ability_details_dict_plus  = { **ability_details__dict, **{"id__dependence__fact": ability,"plugin": plugin} } 

       print(f"id__dependence__fact: {ability_details_dict_plus['id__dependence__fact']}",flush=True)
       print(f"> technique: {ability_details_dict_plus['technique']}",flush=True)
       print(f"> tactic: {ability_details_dict_plus['tactic']}",flush=True)
       print(f"> description: {ability_details_dict_plus['description']}",flush=True)
       print(f"> platforms: {ability_details_dict_plus['platforms']}",flush=True)
       print(f"> plugin: {ability_details_dict_plus['plugin']}",flush=True)
       print("\n", flush=True )


       print(f"id__dependence__fact: {ability_details_dict_plus['id__dependence__fact']}",
             flush=True, file=write_fp)

       print(f"> technique: {ability_details_dict_plus['technique']}"
             ,flush=True, file=write_fp)

       print(f"> tactic: {ability_details_dict_plus['tactic']}",
             flush=True, file=write_fp)

       print(f"> description: {ability_details_dict_plus['description']}",
             flush=True, file=write_fp)
       
       print(f"> platforms: {ability_details_dict_plus['platforms']}"
             ,flush=True, file=write_fp)
       
       print(f"> plugin: {ability_details_dict_plus['plugin']}",
             flush=True, file=write_fp)

       print("\n", 
             flush=True, file=write_fp)


       global_dict[ability_id] = ability_details_dict_plus

   return global_dict

       # adversary_profile_ability_details_dict['platforms'].keys()













if __name__ == "__main__":

    cur_dirpath = "/home/priti/Desktop/caldera/etw/caldera"

    write_filepath = os.path.join(cur_dirpath, "Mitre_TechniqueIDs_for_ablist_JY.txt")

    file_pointer = open(write_filepath, 'w') 

    caldera_ability_id__MitreTechniqueID__map_dict = Get_All_Mitre_TechniqueIDs(file_pointer)

    MitreTechniqueID__caldera_ability_id__map_dict = dict()
    for k,v in caldera_ability_id__MitreTechniqueID__map_dict.items():

        try:
            mitre_technique_id = v['technique']['attack_id'] 
        except:
            mitre_technique_id = v['technique']

        try:
            mitre_technique_name = v['technique']['name'] 
        except:
            mitre_technique_name = "no_name"

        try:
            mitre_tactic = v['tactic'] 
        except:
            print()



        # v = v | {"caldera_ability_id": k}
        v = { **v, **{"caldera_ability_id": k} }

        MitreTechniqueID__caldera_ability_id__map_dict[f"{mitre_technique_id}__{mitre_tactic}__{mitre_technique_name}__{k}"] = v


    caldera_ability_id__MitreTechniqueID__map_dict_path = os.path.join(cur_dirpath, 
                                                                       "caldera_ability_id__MitreTechniqueID__map_dict__ablistJY.json")

    MitreTechniqueID__caldera_ability_id__map_dict_path = os.path.join(cur_dirpath, 
                                                                       "MitreTechniqueID__caldera_ability_id__map_dict__ablistJY.json")

    # also prepare the opposite. key: Mitre_technique_attack_id , value : caldera-ability-id



    with open(caldera_ability_id__MitreTechniqueID__map_dict_path, 'w') as f:
        json.dump(caldera_ability_id__MitreTechniqueID__map_dict, f)
    
    with open(MitreTechniqueID__caldera_ability_id__map_dict_path, 'w') as f:
        json.dump(MitreTechniqueID__caldera_ability_id__map_dict, f)    