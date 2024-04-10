'''
JY @ 2024-04-08: 
TODO 
- Generate caldera- custom-adversary-profiles a.k.a synthetic-APT-attack samples that emulate APT-Group attacks

   * Plan: 

      Generating synthetic-APT-attack samples as a sequence of 3-4 TTPs, TTP per Tactic, 
      sampled from an APT Group’s Tactic-TTP pool, containing secured TTPs that correspond to the specified tactic.
      - Limiting the TTP-sequence length to 3-4 and setting a 1.5-hour post-activity-wait-time to avoid log-loss from streaming-overhead 
        (20-30 minute wait-time per TTP).
      - For TTP-sequence’s tactic-order, referring to the order in MITRE Attack Navigator Layers.

- Refer to:
   -- /home/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Synthetic_APT_Attack_sample__generation/Custom_Adversary_Profile_Generation_Model_v1.py
   
   -- https://docs.google.com/presentation/d/1bQoaqb6r7ldhevMjMUqE7QoA8bRjyM2rSSRDRkntRDE/edit#slide=id.g26d5f408f0b_1_0
   -- https://docs.google.com/presentation/d/1bQoaqb6r7ldhevMjMUqE7QoA8bRjyM2rSSRDRkntRDE/edit#slide=id.g2c91d73bd7c_0_34
   
   -- https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2FG1015%2FG1015-enterprise-layer.json
   -- https://attack.mitre.org/techniques/enterprise/
'''


import json
import random
import itertools
import os
from datetime import datetime
import shutil


with open("/home/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Synthetic_APT_Attack_sample__generation/caldera_ability_id__MitreTechniqueID__map_dict__ablistJY.json", 
          "r") as json_file:
      caldera_ability_id__MitreTechniqueID__map_dict = json.load(json_file)

with open("/home/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Synthetic_APT_Attack_sample__generation/APT_GROUP__TACTIC__SECURED_ABILITIES__saved_at_2024-04-08_213815.json", 
          "r") as json_file:
      APT_GROUP__TACTIC__SECURED_ABILITIES_dict = json.load(json_file)



def sample_preserving_order(lst, n):
   if n >= len(lst):
      return [lst]

   indices_combinations = itertools.combinations(range(len(lst)), n)
   samples = []
   for indices in indices_combinations:
      if list(indices) == sorted(indices):
            samples.append([lst[i] for i in indices])
   return samples

# [ JY @ 2024-04-08 ] : 
# TODO -- Need to deal with TTPs with "multiple"
# -- For example, "T1546.011" with tactic of "multiple :: T1546.011" , 
#                  belongs to "privilege-escalaton" and "persistence"  
#                  based on "https://attack.mitre.org/techniques/T1546/011/"
# 
MITRE_Attack_Navigator_Layer__Ordered_Tactic_Sequence = \
["reconnaissance", 
#  "resource development", # -- none of the TTPs belong to 'resource development'
 "initial-access",
 "execution", 
 "persistence",
 "privilege-escalation",
 "defense-evasion",
 "credential-access",
 "discovery",
 "lateral-movement",
 "collection",
 "command-and-control",
 "exfiltration",
 "impact",
]

if __name__ == "__main__":

   # ==========================================================================================================
   # Set -- 
   TTP_sequence_length = 3

   Custom_Adv_Profile_SaveDirpath = "/home/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Synthetic_APT_Attack_sample__generation/Synthetic_APT_Attack_Custom_Adv_Profile_yml_files"

   # ==========================================================================================================
   # Generate all possible dissimilar attacks 

   APT_GROUP__TACTIC__SECURED_ABILITIES_dict
   caldera_ability_id__MitreTechniqueID__map_dict


   APTGroup__syntheticAPTattack__TTPsequence__dict = dict()

   total_number_of_samples_cnt = 0

   for APT_GROUP, TACTIC__SECURED_ABILITIES_dict in APT_GROUP__TACTIC__SECURED_ABILITIES_dict.items():


      APT_GROUP_AVAILABLE_TACTICS = TACTIC__SECURED_ABILITIES_dict.keys()

      if TTP_sequence_length > len(APT_GROUP_AVAILABLE_TACTICS) :
          print(f"can't do this APTGroup {APT_GROUP} since only {len(APT_GROUP_AVAILABLE_TACTICS)} APT_GROUP_AVAILABLE_TACTICS -- {APT_GROUP_AVAILABLE_TACTICS}", flush=True)
          continue
      APTGroup__syntheticAPTattack__TTPsequence__dict[APT_GROUP] = list()


      APT_GROUP_AVAILABLE_TACTICS__following_MITRE_Ordering = [ tactic for tactic in MITRE_Attack_Navigator_Layer__Ordered_Tactic_Sequence 
                                                                if tactic in APT_GROUP_AVAILABLE_TACTICS ]
      APT_GROUP_All_Possible_Tactic_Sequences_preserving_MITRE_Ordering = sample_preserving_order( APT_GROUP_AVAILABLE_TACTICS__following_MITRE_Ordering , 
                                                                                                   TTP_sequence_length )

      for APT_GROUP_Tactic_Sequence_preserving_MITRE_Ordering in APT_GROUP_All_Possible_Tactic_Sequences_preserving_MITRE_Ordering:
         syntheticAPTattack__TTPsequence = []       
         for tactic in APT_GROUP_Tactic_Sequence_preserving_MITRE_Ordering:
            
            APT_Group_tactic_secured_abilities = TACTIC__SECURED_ABILITIES_dict[tactic]
            ability = random.sample(APT_Group_tactic_secured_abilities, 1)[0]
            syntheticAPTattack__TTPsequence.append( (ability, tactic) )

            todo = True

         total_number_of_samples_cnt += 1
         APTGroup__syntheticAPTattack__TTPsequence__dict[APT_GROUP].append( syntheticAPTattack__TTPsequence )
         todo = True
      todo = True

   todo = True
   
   # ===============================================================================================================
   # Now start generating custom-adv-profile files
   

   def generate_adv_yml_file_text(syntheticAPTattack_TTPsequence_input, 
                                  custom_adversary_profile_description_input,
                                  Custom_Adv_Profile_SaveDirpath_input):

      adversary_id = f"custom_adversary_profile__{custom_adversary_profile_description_input}__{datetime.now().strftime('%Y-%m-%d-%H_%M_%S')}"

      # not having '[' and ']' is very important.
      first = f"""adversary_id: {adversary_id}\nname: Custom Adversary Profile\ndescription: {str(custom_adversary_profile_description_input).replace('[','__').replace(']','').replace(' ','')}\natomic_ordering:\n"""

      mid = ""
      # for ab_tuple in ab_tuple_list:

      for ab_tactic_tuple in syntheticAPTattack_TTPsequence_input:
         ability_id = ab_tactic_tuple[0]
         ability_tactic = ab_tactic_tuple[1]

         mid += f"- {ability_id} # {ability_tactic} ; {caldera_ability_id__MitreTechniqueID__map_dict[ability_id]['technique']} - {caldera_ability_id__MitreTechniqueID__map_dict[ability_id]['technique']['attack_id']}; {caldera_ability_id__MitreTechniqueID__map_dict[ability_id]}\n"
      last  ="""objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc\ntags: []"""

      custom_adversary_yml_file_text = first + mid + last

      with open( os.path.join( Custom_Adv_Profile_SaveDirpath_input, f'{adversary_id}.yml') ,'w') as f:    # Modified by JY @ 2023-02-27
            f.write( custom_adversary_yml_file_text )


   if os.path.exists(Custom_Adv_Profile_SaveDirpath):
       shutil.rmtree(Custom_Adv_Profile_SaveDirpath)
   os.makedirs(Custom_Adv_Profile_SaveDirpath)
   
   for APTGroup, syntheticAPTattack_TTPsequences_list in APTGroup__syntheticAPTattack__TTPsequence__dict.items():
       print(f"{APTGroup}", flush=True)

       for syntheticAPTattack_TTPsequence in syntheticAPTattack_TTPsequences_list:
           
           if APTGroup == "Machete (G0095)":
               to_debug = True
           
           tactic_sequence = "__".join([x[1] for x in syntheticAPTattack_TTPsequence])

           generate_adv_yml_file_text( syntheticAPTattack_TTPsequence_input = syntheticAPTattack_TTPsequence,
                                       custom_adversary_profile_description_input = f"{APTGroup}__{tactic_sequence}".replace(" ", "_").replace("(","").replace(")","").replace("@","").replace("-","_") ,
                                       Custom_Adv_Profile_SaveDirpath_input = Custom_Adv_Profile_SaveDirpath)


