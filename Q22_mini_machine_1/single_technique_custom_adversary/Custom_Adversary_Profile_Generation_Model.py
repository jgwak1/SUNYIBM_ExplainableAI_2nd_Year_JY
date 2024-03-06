import os
from pathlib import Path
import shutil


import json
import pickle
import yaml

import random
import types
from datetime import datetime


from stockpile_atomic_plugin_ability_ids import *  # includes all ability-id lists per plugin-tactic
                                                   # e.g. 'stockpile_privilege_escalation__ability_ids'


STOCKPILE__COLLECTION = "stockpile__collection"
STOCKPILE__COMMAND_AND_CONTROL = "stockpile__command-and-control"
STOCKPILE__CREDENTIAL_ACCESS = "stockpile__credential-access"
STOCKPILE__DEFENSE_EVASION = "stockpile__defense-evasion"
STOCKPILE__DISCOVERY = "stockpile__discovery"
STOCKPILE__EXECUTION = "stockpile__execution"
STOCKPILE__EXFILTRATION = "stockpile__exfiltration"
STOCKPILE__IMPACT = "stockpile__impact"
STOCKPILE__LATERAL_MOVEMENT = "stockpile__lateral-movement"
STOCKPILE__PERSISTENCE = "stockpile__persistence"
STOCKPILE__PRIVILEGE_ESCALATION = "stockpile__privilege_escalation"

ATOMIC__COLLECTION = "atomic__collection"
ATOMIC__COMMAND_AND_CONTROL = "atomic__command-and-control"
ATOMIC__CREDENTIAL_ACCESS = "atomic__credential-access"
ATOMIC__DEFENSE_EVASION = "atomic__defense-evasion"
ATOMIC__DISCOVERY = "atomic__discovery"
ATOMIC__EXECUTION = "atomic__execution"
ATOMIC__EXFILTRATION = "atomic__exfiltration"
ATOMIC__IMPACT = "atomic__impact"
ATOMIC__LATERAL_MOVEMENT = "atomic__lateral-movement"
ATOMIC__PERSISTENCE = "atomic__persistence"
ATOMIC__PRIVILEGE_ESCALATION = "atomic__privilege_escalation"

ATOMIC__INITIAL_ACCESS = "atomic__initial_access"
ATOMIC__MULTIPLE = "atomic__initial_access"
ATOMIC__RECONNAISSANCE = "atomic__reconnaissance"

STOCKPILE__ALL_TACTICS = [STOCKPILE__COLLECTION, STOCKPILE__COMMAND_AND_CONTROL, STOCKPILE__CREDENTIAL_ACCESS, STOCKPILE__DEFENSE_EVASION,
                          STOCKPILE__DISCOVERY, STOCKPILE__EXECUTION, STOCKPILE__EXFILTRATION, STOCKPILE__IMPACT, STOCKPILE__LATERAL_MOVEMENT,
                          STOCKPILE__PERSISTENCE, STOCKPILE__PRIVILEGE_ESCALATION]

ATOMIC__ALL_TACTICS = [ATOMIC__COLLECTION, ATOMIC__COMMAND_AND_CONTROL, ATOMIC__CREDENTIAL_ACCESS, ATOMIC__DEFENSE_EVASION, 
                       ATOMIC__DISCOVERY, ATOMIC__EXECUTION, ATOMIC__EXFILTRATION, ATOMIC__IMPACT, ATOMIC__LATERAL_MOVEMENT,
                       ATOMIC__PERSISTENCE, ATOMIC__PRIVILEGE_ESCALATION, ATOMIC__INITIAL_ACCESS, ATOMIC__MULTIPLE, ATOMIC__RECONNAISSANCE]

BOTH__ALL_TACTICS = STOCKPILE__ALL_TACTICS + ATOMIC__ALL_TACTICS

f1 = open('/home/etw0/Desktop/caldera/etw/caldera/MitreTechniqueID__caldera_ability_id__map_dict__ablistJY.json')
MitreTechniqueID__caldera_ability_id__map_dict = json.load(f1)

f2 = open("/home/etw0/Desktop/caldera/etw/caldera/caldera_ability_id__MitreTechniqueID__map_dict__ablistJY.json")
caldera_ability_id__MitreTechniqueID__map_dict = json.load(f2)

# JY: If need to also incorporate ATOMIC later together with stockpile, --> BOTH_PLUGINS__COLLECTION 

class Custom_Adversary_Profile_Generation_Model_v1:

   '''  Model (Version-1) : Technique-selection strategy

         Model takes as input:
         - List of techniques: could be all techniques, or narrow down to ones used by a specific activity-group (e.g. APT 29).
         - Sequence of tactics: handles pre-defined tactic-execution-orders; can also handle “all or subset of tactics w/o order”

         1. Based on inputs, sample the initial non-dependent technique, prioritizing those that yield a fact. 

         2. Sample techniques from pre-defined search-space, prioritizing those dependent on a collected fact and fact-yielding.
            * If none are dependent or fact-yielding, then random-sample.
            * Duplicate technique sampling disabled.  '''

   def __init__(self, 
                profile_length : int = 7,
                plugin : str = "both", # "stockpile", "atomic", "both"
                list_of_technique_ids : list = None, # default None ==  All techniques (All caldera-abilities)
                sequence_of_tactics : list = None, # default None == No sequence, all tactics w/o order
                custom_adversary_profile_yml_dirpath : str = None,
                custom_adversary_profile_description : str = None,
                sampling_weight_for_factyielding_abs : int = 2,   # integer
                sampling_weight_for_non_factyielding_abs : int = 1, # integer
                ) -> None:

      
      if sequence_of_tactics == None or sequence_of_tactics == []:         # all available activities.
         self.profile_length = profile_length
      else:
         self.profile_length = len(sequence_of_tactics)        # if there is a specified sequence (tactic-execution-order)


      self.sampling_weight_for_factyielding_abs = sampling_weight_for_factyielding_abs
      self.sampling_weight_for_non_factyielding_abs = sampling_weight_for_non_factyielding_abs

      plugin_choices = {"stockpile", "atomic", "both"}
      if plugin not in plugin_choices:
         raise ValueError(f"plugin should be one of {plugin_choices}", flush = True)
      self.plugin = plugin
      
      self.custom_adversary_profile_yml_dirpath = custom_adversary_profile_yml_dirpath
      self.custom_adversary_profile_description = custom_adversary_profile_description
      self.ab_tuple_list = pickle.load( open( os.path.join( str(Path(__file__).parent), 'ab_list__JY.pkl') ,'rb' ) ) # zhan's ab_tuple_list

      self.list_of_ability_ids = self.get_list_of_ability_ids( list_of_technique_ids )

      if sequence_of_tactics == None or sequence_of_tactics == []:
         if self.plugin == "stockpile":
            self.sequence_of_tactics = [ STOCKPILE__ALL_TACTICS ]
         elif self.plugin == "atomic":
            self.sequence_of_tactics = [ ATOMIC__ALL_TACTICS ]
         else:
            self.sequence_of_tactics = [ BOTH__ALL_TACTICS ]
      else:
         self.sequence_of_tactics = sequence_of_tactics
      
      self.sequence_of_tactics_abilitiy_ids = self.create_sequence_of_tactics_ability_ids()


   def get_list_of_ability_ids(self, list_of_technique_ids ) -> list:

      ''' Get corresponding caldera-ability_ids from Mitre-technique-ids '''

      # keys are in form of "<technique-id>__<tactic>__<technique-name>__<caldera_ability_id>"
      # e.g. "T1543.003__persistence__Create or Modify System Process: Windows Service__52771610-2322-44cf-816b-a7df42b4c086"
      stockpile_keys = [k for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if v['plugin'] == "stockpile"]
      atomic_keys = [k for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if v['plugin'] == "atomic"]

      # For now (2023/10/18), only considering the stockpile abilities.
      delim = "__"
      stockpile_splitted_keys = [key.split(delim) for key in stockpile_keys]
      atomic_splitted_keys = [key.split(delim) for key in atomic_keys]



      if list_of_technique_ids == None or list_of_technique_ids == []:
         # set as all stockpile caldera-ability-ids 
         stockpile_caldera_ability_ids = [x[-1] for x in stockpile_splitted_keys]
         atomic_caldera_ability_ids = [x[-1] for x in atomic_splitted_keys]

         if self.plugin == "stockpile":
            list_of_ability_ids = stockpile_caldera_ability_ids
         elif self.plugin == "atomic":
            list_of_ability_ids = atomic_caldera_ability_ids
         else:
            list_of_ability_ids = stockpile_caldera_ability_ids + atomic_caldera_ability_ids

      else:
         # Only the stockpile caldera-ability-ids that correspond to the inputted 'list_of_technique_ids'
         # Don't make it into a direct-mapping of technique-id to caldera-ability
         # B/c it's a one-to-many relationship,it should be map from technique-id to list of caldera-abilities
         
         stockpile_id_one_to_many_map = {}
         for key in stockpile_splitted_keys:
            if key[0] in stockpile_id_one_to_many_map:
               stockpile_id_one_to_many_map[key[0]].append(key[-1])
            else:
               stockpile_id_one_to_many_map[key[0]] = [key[-1]]      

         atomic_id_one_to_many_map = {}
         for key in atomic_splitted_keys:
            if key[0] in atomic_id_one_to_many_map:
               atomic_id_one_to_many_map[key[0]].append(key[-1])
            else:
               atomic_id_one_to_many_map[key[0]] = [key[-1]]      


         list_of_technique_ids_lowercase = [ x.lower() for x in list_of_technique_ids ]


         if self.plugin == "stockpile":
            list_of_ability_ids = [ v for k,v in stockpile_id_one_to_many_map.items() if k.lower() in list_of_technique_ids_lowercase ]
         elif self.plugin == "atomic":
            list_of_ability_ids = [ v for k,v in atomic_id_one_to_many_map.items() if k.lower() in list_of_technique_ids_lowercase ]
         else:
            #both_plugins_id_one_to_many_map = stockpile_id_one_to_many_map | atomic_id_one_to_many_map
            both_plugins_id_one_to_many_map = {**stockpile_id_one_to_many_map , **atomic_id_one_to_many_map }
            list_of_ability_ids = [ v for k,v in both_plugins_id_one_to_many_map.items() if k.lower() in list_of_technique_ids_lowercase ]


         list_of_ability_ids = sum(list_of_ability_ids, []) # need to flatten

      return list_of_ability_ids


   def create_sequence_of_tactics_ability_ids(self) -> list:
      ''' Based on 'list_of_techniques' and 'sequence_of_tactics',
          creates and returns a list of list, 
          where sublists correspond to tactics specified in 'sequence_of_tactics',
          and elements of sublist correspond to ability-ids of the corresponding tactic but only those included in 'list_of_techniques'. '''

      ret_list = []

      def get_selected_tactic_ability_ids( tactic__ability_ids ):
         selected_tactic_ability_ids = set(tactic__ability_ids).intersection(set( self.list_of_ability_ids ) )
         return list(selected_tactic_ability_ids)

      for tactic_sublist in self.sequence_of_tactics:

         ret_sublist = []
         for tactic in tactic_sublist:
            
            if tactic == STOCKPILE__COLLECTION: ret_sublist += get_selected_tactic_ability_ids(stockpile_collection__ability_ids) 
            if tactic == STOCKPILE__COMMAND_AND_CONTROL:  ret_sublist += get_selected_tactic_ability_ids(stockpile_command_and_control__ability_ids) 
            if tactic == STOCKPILE__CREDENTIAL_ACCESS:  ret_sublist += get_selected_tactic_ability_ids(stockpile_credential_access__ability_ids) 
            if tactic == STOCKPILE__DEFENSE_EVASION: ret_sublist += get_selected_tactic_ability_ids(stockpile_defense_evasion__ability_ids) 
            if tactic == STOCKPILE__DISCOVERY: ret_sublist += get_selected_tactic_ability_ids(stockpile_discovery__ability_ids) 
            if tactic == STOCKPILE__EXECUTION: ret_sublist += get_selected_tactic_ability_ids(stockpile_execution__ability_ids) 
            if tactic == STOCKPILE__EXFILTRATION: ret_sublist += get_selected_tactic_ability_ids(stockpile_exfiltration__ability_ids) 
            if tactic == STOCKPILE__IMPACT: ret_sublist += get_selected_tactic_ability_ids(stockpile_impact__ability_ids) 
            if tactic == STOCKPILE__LATERAL_MOVEMENT: ret_sublist += get_selected_tactic_ability_ids(stockpile_lateral_movement__ability_ids ) 
            if tactic == STOCKPILE__PERSISTENCE: ret_sublist += get_selected_tactic_ability_ids(stockpile_persistence__ability_ids) 
            if tactic == STOCKPILE__PRIVILEGE_ESCALATION: ret_sublist += get_selected_tactic_ability_ids(stockpile_privilege_escalation__ability_ids) 

            if tactic == ATOMIC__COLLECTION: ret_sublist += get_selected_tactic_ability_ids(atomic_collection__ability_ids) 
            if tactic == ATOMIC__COMMAND_AND_CONTROL:  ret_sublist += get_selected_tactic_ability_ids(atomic_command_and_control__ability_ids) 
            if tactic == ATOMIC__CREDENTIAL_ACCESS:  ret_sublist += get_selected_tactic_ability_ids(atomic_credential_access__ability_ids) 
            if tactic == ATOMIC__DEFENSE_EVASION: ret_sublist += get_selected_tactic_ability_ids(atomic_defense_evasion__ability_ids) 
            if tactic == ATOMIC__DISCOVERY: ret_sublist += get_selected_tactic_ability_ids(atomic_discovery__ability_ids) 
            if tactic == ATOMIC__EXECUTION: ret_sublist += get_selected_tactic_ability_ids(atomic_execution__ability_ids) 
            if tactic == ATOMIC__EXFILTRATION: ret_sublist += get_selected_tactic_ability_ids(atomic_exfiltration__ability_ids) 
            if tactic == ATOMIC__IMPACT: ret_sublist += get_selected_tactic_ability_ids(atomic_impact__ability_ids) 
            if tactic == ATOMIC__LATERAL_MOVEMENT: ret_sublist += get_selected_tactic_ability_ids(atomic_lateral_movement__ability_ids ) 
            if tactic == ATOMIC__PERSISTENCE: ret_sublist += get_selected_tactic_ability_ids(atomic_persistence__ability_ids) 
            if tactic == ATOMIC__PRIVILEGE_ESCALATION: ret_sublist += get_selected_tactic_ability_ids(atomic_privilege_escalation__ability_ids) 

            if tactic == ATOMIC__INITIAL_ACCESS: ret_sublist += get_selected_tactic_ability_ids(atomic_initial_access__ability_ids) 
            if tactic == ATOMIC__MULTIPLE: ret_sublist += get_selected_tactic_ability_ids(atomic_multiple__ability_ids) 
            if tactic == ATOMIC__RECONNAISSANCE: ret_sublist += get_selected_tactic_ability_ids(atomic_reconnaissance__ability_ids) 


         ret_list.append(ret_sublist)

      return ret_list


   def search_from_ab_list(self, 
                           ability_id: str ) -> tuple:
      ''' Searches from zhan's ab_tuple_list and 
          returns the tuple (id, dependency, fact) if matching ability_id found, else return None ''' 
      for tup in self.ab_tuple_list: 
         if tup[0] == ability_id:
               return tup         
      return None 


   def get_tactic_available_ab(self, 
                               collected_facts_list : list, 
                               target_tactic_ability_pool_id_list : list):
      ''' Based on the collected-facts, 
          get all available ability-tuples from the passed target-tactic ability pool
          (if there exists abilities that are dependent to any of the collected-facts, those will be the available abilities
           else all abilities from the passed target-tactic ability pool will be the available abilities.)

          Returns list of ability_tuples
      '''

      target_tactic_ability_pool_tuple_list = list( filter(lambda v: v is not None, 
                                                [ self.search_from_ab_list(ability_id) for ability_id in target_tactic_ability_pool_id_list ]) )   
      target_tactic__available_ab_tuple_list = []
      
      for ab_tuple in target_tactic_ability_pool_tuple_list:   
         dependency = ab_tuple[1]
         if dependency in collected_facts_list:
            target_tactic__available_ab_tuple_list.append(ab_tuple)
             
      # if none of the tactic-abilities exploit the collected-facts, then just return the whole tactic-ability-id-list
      if len(target_tactic__available_ab_tuple_list) == 0:
          target_tactic__available_ab_tuple_list = target_tactic_ability_pool_tuple_list
   
      return target_tactic__available_ab_tuple_list


   def generate_custom_adv_profile(self):
      
      ''' TODO

      Based on inputs, sample the initial non-dependent technique, prioritizing those that yield a fact. 
      If none are dependent or fact-yielding, then random-sample.
      Duplicate technique sampling disabled.

      Implementing fact-yielding priority here.
      
      Implement saving yaml
      > refer to : /data/d1/jgwak1/tabby/tools__Copied_from_home_zshu1_tools__run_on_panther/tools__Copied_from_home_zhsu1_tools/etw/caldera/generate_adv.py

      '''

      custom_adversary_profile_abilities = []
      collected_facts = []

      while (True):

         while_break = False

         for current_tactic_ability_ids in self.sequence_of_tactics_abilitiy_ids:
            
            if len(current_tactic_ability_ids) == 0:
               continue

            selected_abilitiy_tuple = None

            # if sampling the first ability, 
            # sample the initial non-dependent technique, prioritizing those that yield a fact. 
            if len(custom_adversary_profile_abilities) == 0: 
            
               current_tactic_ability_tuple_list = list( filter(lambda v: v is not None, [ self.search_from_ab_list(ability_id) for ability_id in current_tactic_ability_ids ]) )
               current_tactic_non_dependent_ability_tuple_list = [ x for x in current_tactic_ability_tuple_list if x[1] == "None" ]

               if len(current_tactic_non_dependent_ability_tuple_list) == 0:
                  continue               

               sampling_weights = [ self.sampling_weight_for_factyielding_abs if tup[2] not in ["None", "validate_me"] else self.sampling_weight_for_non_factyielding_abs  
                                    for tup in current_tactic_non_dependent_ability_tuple_list ]
               selected_abilitiy_tuple = random.choices(current_tactic_non_dependent_ability_tuple_list, 
                                                        weights=sampling_weights, 
                                                        k=1)[0]
               custom_adversary_profile_abilities.append(selected_abilitiy_tuple)

            else: 
               current_tactic_available_ability_tuple_list = self.get_tactic_available_ab(collected_facts, current_tactic_ability_ids)  # Get the 'available' abilities
               # Potential duplicate abilities handling 
               potential_duplicate_ability_ids_set = {x[0] for x in custom_adversary_profile_abilities}.intersection( {x[0] for x in current_tactic_available_ability_tuple_list} )            
               current_tactic_available_duplicate_prevented_ability_tuple_list = [ x for x in current_tactic_available_ability_tuple_list if x[0] not in potential_duplicate_ability_ids_set ]
               # -- if available abilities become 0 after potential-duplicate-handling, just allow duplicates only in this case
               if len(current_tactic_available_duplicate_prevented_ability_tuple_list) == 0:
                  current_tactic_available_duplicate_prevented_ability_tuple_list = current_tactic_available_ability_tuple_list
               sampling_weights = [ self.sampling_weight_for_factyielding_abs if tup[2] not in ["None", "validate_me"] else self.sampling_weight_for_non_factyielding_abs  
                                    for tup in current_tactic_available_duplicate_prevented_ability_tuple_list ]
               selected_abilitiy_tuple = random.choices(current_tactic_available_duplicate_prevented_ability_tuple_list, 
                                                        weights=sampling_weights, 
                                                        k=1)[0]
               custom_adversary_profile_abilities.append(selected_abilitiy_tuple)


            # Update collected_facts ; we don't want duplicate-facts, 'None', and 'validate_me' 
            if (selected_abilitiy_tuple[2] not in collected_facts) and (selected_abilitiy_tuple[2] not in ['None', 'validate_me']):          
               collected_facts.append( selected_abilitiy_tuple[2] )
               
            if ( len(custom_adversary_profile_abilities) == self.profile_length ):
               while_break = True
               break
                     
         if while_break == True:
            break

      self.generate_adv_yml_file_text( ab_tuple_list = custom_adversary_profile_abilities)

      return custom_adversary_profile_abilities

   # TODO -- generate_adv and also incorporate atomic

   def generate_adv_yml_file_text(self, ab_tuple_list):

      adversary_id = f"custom_adversary_profile__{self.custom_adversary_profile_description}__{datetime.now().strftime('%Y-%m-%d-%H_%M_%S')}"

      # not having '[' and ']' is very important.
      first = f"""adversary_id: {adversary_id}\nname: Custom Adversary Profile\ndescription: {str(sequence_of_tactics).replace('[','__').replace(']','').replace(' ','')}\natomic_ordering:\n"""
      mid = ""
      for ab_tuple in ab_tuple_list:
         mid += f"- {ab_tuple[0]} # {ab_tuple} ; {caldera_ability_id__MitreTechniqueID__map_dict[ab_tuple[0]]['tactic']} ; {caldera_ability_id__MitreTechniqueID__map_dict[ab_tuple[0]]['technique']} - {caldera_ability_id__MitreTechniqueID__map_dict[ab_tuple[0]]['technique']['attack_id']}; {caldera_ability_id__MitreTechniqueID__map_dict[ab_tuple[0]]}\n"
      last  ="""objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc\ntags: []"""

      custom_adversary_yml_file_text = first + mid + last

      with open( os.path.join( self.custom_adversary_profile_yml_dirpath, f'{adversary_id}.yml') ,'w') as f:    # Modified by JY @ 2023-02-27
            f.write( custom_adversary_yml_file_text )

      # shutil.copy('b176f4b1-a582-4774-b6f6-46a2e11480af.yml','/home/zshu1/tools/caldera/data/adversaries/') 
      # shutil.copy( os.path.join( str(Path(__file__).parent), 'b176f4b1-a582-4774-b6f6-46a2e11480af.yml'),'/home/jgwak1/tools__Copied_from_home_zhsu1_tools/caldera/data/adversaries/') # Modified by JY @ 2023-02-27
      


if __name__ == "__main__":


   # none, apt_3
   threat_group_choice = "none"

   # none, ...
   # apt3_phase2_pattern_1, apt3_phase2_pattern_2 , apt3_phase2_pattern_3 , 
   # apt3_phase3_pattern_1 , apt3_phase3_pattern_2,
   # survey_paper_apt_attack_six_phases
   sequence_of_tactics_choice = "survey_paper_apt_attack_six_phases"
   
   # stockpile , atomic, both
   plugin_choice = "both"




   #############################################################################################################################
   default_profile_length = 7
   custom_adversary_profile_yml_dirpath = \
   "/home/priti/Desktop/caldera/etw/caldera/Custom_Adversary_Profile_yml_files"  
   #############################################################################################################################
   # https://attack.mitre.org/groups/

   ThreatGroup_Techniques_dict = dict()
   ThreatGroup_Techniques_dict["apt_3"] = ["T1087.001", "T1098", "T1560.001", "T1547.001", "T1110.002", "T1059.001", 
                                           "T1059.003", "T1136.001", "T1543.003" , "T1555.003" , "T1005" , "T1074.001",
                                           "T1546.008", "T1041", "T1203", "T1083", "T1564.003", "T1574.002",
                                           "T1070.004", "T1105", "T1056.001", "T1104", "T1095", "T1027.002",
                                           "T1027.005", "T1003.001", "T1069", "T1566.002", "T1057", "T1090.002",
                                           "T1021.001", "T1021.002", "T1018", "T1053.005", "T1218.011", "T1082",
                                           "T1016", "T1049", "T1033", "T1552.001", "T1204.001", "T1078.002"]
   ThreatGroup_Techniques_dict["none"] = None 


   # list_of_technique_ids = None # all techniques will be considered
   list_of_technique_ids = ThreatGroup_Techniques_dict[threat_group_choice]

   #############################################################################################################################
   # Should be in form of list of lists
   # e.g.
   #     "Privilege-Escalation --> Credentil-Access --> Execution" 
   #       == [ [STOCKPILE__PRIVILEGE_ESCALATION], [STOCKPILE__CREDENTIAL_ACCESS], [STOCKPILE__EXECUTION] ]
   #      
   #     "Privilege-Escalation/Credentil-Access --> Execution" 
   #       == [ [STOCKPILE__PRIVILEGE_ESCALATION, STOCKPILE__CREDENTIAL_ACCESS], [STOCKPILE__EXECUTION] ]
   #
   #     "Privilege-Escalation/Credentil-Access/Execution" 
   #       == [ [STOCKPILE__PRIVILEGE_ESCALATION, STOCKPILE__CREDENTIAL_ACCESS, STOCKPILE__EXECUTION] ]
   

   Sequence_of_Tactics_Pattern_dict = dict()
   
   # APT3 Emulation Plans : https://attack.mitre.org/resources/adversary-emulation-plans/
   Sequence_of_Tactics_Pattern_dict["apt3_phase2_pattern_1"] = \
      [  # phase-2: Privilege-Escalation --> Persistence --> Lateral-Movement --> Execution
         [STOCKPILE__PRIVILEGE_ESCALATION, ATOMIC__PRIVILEGE_ESCALATION],
         [STOCKPILE__PERSISTENCE, ATOMIC__PERSISTENCE],
         [STOCKPILE__LATERAL_MOVEMENT, ATOMIC__LATERAL_MOVEMENT],
         [STOCKPILE__EXECUTION, ATOMIC__EXECUTION]
      ] 
   
   Sequence_of_Tactics_Pattern_dict["apt3_phase2_pattern_2"] = \
      [  # phase-2: Privilege-Escalation --> Credential-Access --> Lateral-Movement --> Execution
         [STOCKPILE__PRIVILEGE_ESCALATION, ATOMIC__PRIVILEGE_ESCALATION],
         [STOCKPILE__CREDENTIAL_ACCESS, ATOMIC__CREDENTIAL_ACCESS],
         [STOCKPILE__LATERAL_MOVEMENT, ATOMIC__LATERAL_MOVEMENT],
         [STOCKPILE__EXECUTION, ATOMIC__EXECUTION]
      ] 


   Sequence_of_Tactics_Pattern_dict["apt3_phase2_pattern_3"] = \
      [  # phase-2: Discovery --> Lateral Movement --> Execution
         [STOCKPILE__DISCOVERY, ATOMIC__DISCOVERY],
         [STOCKPILE__LATERAL_MOVEMENT, ATOMIC__LATERAL_MOVEMENT],
         [STOCKPILE__EXECUTION, ATOMIC__EXECUTION]
      ] 

   Sequence_of_Tactics_Pattern_dict["apt3_phase3_pattern_1"] = \
      [  # phase-2: Defense Evasion --> Lateral Movement --> Execution
         [STOCKPILE__DEFENSE_EVASION, ATOMIC__DEFENSE_EVASION],
         [STOCKPILE__LATERAL_MOVEMENT, ATOMIC__LATERAL_MOVEMENT],
         [STOCKPILE__EXECUTION, ATOMIC__EXECUTION]
      ] 

   Sequence_of_Tactics_Pattern_dict["apt3_phase3_pattern_2"] = \
      [  # phase-2: Collection --> Exfiltrate
         [STOCKPILE__COLLECTION, ATOMIC__COLLECTION],
         [STOCKPILE__EXFILTRATION, ATOMIC__EXFILTRATION],
      ] 

   Sequence_of_Tactics_Pattern_dict["survey_paper_apt_attack_six_phases"] = \
      [  # Survey paper (currently under Prof Guanhua's review) : "Amalgamation of Divergent Logs for Detection of Advanced Persistent Threats in Cyber Threat Analysis"
         #
         # Reconnaissance → Initial Access → Command & Control → Lateral Movement → Privilege Escalation → Exfiltration 
         # [ATOMIC__RECONNAISSANCE], # get rid of reconnaissance as only 1 available 
         [ATOMIC__INITIAL_ACCESS],
         [STOCKPILE__COMMAND_AND_CONTROL, ATOMIC__COMMAND_AND_CONTROL],
         [STOCKPILE__LATERAL_MOVEMENT, ATOMIC__LATERAL_MOVEMENT],
         [STOCKPILE__PRIVILEGE_ESCALATION, ATOMIC__PRIVILEGE_ESCALATION],
         [STOCKPILE__EXFILTRATION, ATOMIC__EXFILTRATION]
      ]
   
   Sequence_of_Tactics_Pattern_dict["none"] = None


   # sequence_of_tactics_choice = None
   sequence_of_tactics = Sequence_of_Tactics_Pattern_dict[ sequence_of_tactics_choice ]

   #############################################################################################################################
   gen_mod = Custom_Adversary_Profile_Generation_Model_v1(list_of_technique_ids = list_of_technique_ids,
                                                          sequence_of_tactics = sequence_of_tactics, 
                                                          profile_length = default_profile_length,
                                                          plugin = plugin_choice,
                                                          custom_adversary_profile_yml_dirpath = custom_adversary_profile_yml_dirpath,
                                                          custom_adversary_profile_description = f"{threat_group_choice}__{sequence_of_tactics_choice}__{plugin_choice}"
                                                         )
   gen_mod.generate_custom_adv_profile()