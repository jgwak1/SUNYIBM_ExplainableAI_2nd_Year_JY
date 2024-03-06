import os
from pathlib import Path
import shutil


import json
import pickle
import yaml

import random
import types
from datetime import datetime
from collections import Counter
import itertools

from stockpile_atomic_plugin_ability_ids import *  # includes all ability-id lists per plugin-tactic
                                                   # e.g. 'stockpile_privilege_escalation__ability_ids'

from Custom_Adversary_Profile_Generation_Model import *


# JY @ 2024-3-6: windows?
#                only powershell? 
#                dependency? no_depend?
#                
#                Refer to:
#                 /home/etw0/Desktop/caldera/etw/caldera/MitreTechniqueID__caldera_ability_id__map_dict__ablistJY.json

class Single_Adversary_Profile_Generation_Model( Custom_Adversary_Profile_Generation_Model_v1 ):

   # implement "def generate_single_technique_adv_profiles(self)"
   # override "generate_adv_yml_file_text()" function for more straightforward yml file-name

   def generate_single_technique_adv_profiles(self, 
                                              plugin = "atomic",

                                              platform = "windows", # Added by JY @ 2024-3-6
                                              depend = False, # Added by JY @ 2024-3-6
                                              powershell = True, # Added by JY @ 2024-3-6

                                              N = None):
       
      ''' For a given plugin, for each technique, generate N single-technique adversary profiles '''


      # Following 2 parameters should be already handled in constructor,
      # but just explicitly set here again, as these two are most important parameters for "get_list_of_ability_ids"
      
      # Added by JY @ 2024-3-6

      if platform not in ['windows']: # just disregard 'linux' since not running on it.
         raise ValueError("platform not in ['windows']")
      self.platform = platform

      if plugin not in ['atomic', 'stockpile']:
         raise ValueError("plugin not in ['atomic', 'stockpile']")
      self.plugin = plugin

      if type(depend) != bool or type(powershell) != bool:
          raise ValueError("type(depend) != bool or type(powershell) != bool")
      self.depend = str(depend)  
      self.powershell = str(powershell) 
      # --------------------------------------------------------------------------------------------------

      # # keys are in form of "<technique-id>__<tactic>__<technique-name>__<caldera_ability_id>"
      # # e.g. "T1543.003__persistence__Create or Modify System Process: Windows Service__52771610-2322-44cf-816b-a7df42b4c086"
      # stockpile_keys = [k for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if v['plugin'] == "stockpile"]
      # atomic_keys = [k for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if v['plugin'] == "atomic"]

      # ------------------------
      # Added by JY @ 2024-3-6
      #     keys are in form of "<technique-id>__<tactic>__<technique-name>__<caldera_ability_id>"
      #     e.g. "T1543.003__persistence__Create or Modify System Process: Windows Service__52771610-2322-44cf-816b-a7df42b4c086"

      #   Counter( list(itertools.chain(*[ list(v['platforms']) for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items()])) )
      #   --> Counter({'windows': 620, 'linux': 41, 'darwin': 32, 'unknown': 32})
      windows_platform_keys = [k for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if 'windows' in v['platforms']]
      
      # windows -- stockpile plugin
      windows_stockpile_keys = [k for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if k in windows_platform_keys and v['plugin'] == "stockpile"]

      # windows -- atomic plugin
      windows_atomic_keys = [k for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if k in windows_platform_keys and v['plugin'] == "atomic"]

      # windows -- no-depend ( doesn't depend on a particular fact/piece-of-information obtained from another ability )
      windows_no_depend_keys = [k for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if k in windows_platform_keys and v['id__dependence__fact'][1] == 'None' ]
      # windows -- depend
      windows_depend_keys = [k for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if k in windows_platform_keys and v['id__dependence__fact'][1] != 'None' ]
      
      # windows -- psh (there's also pshw or something)
         #  [v['platforms']['windows'] for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if k in windows_platform_keys ]
         #  [ list(v['platforms']['windows']) for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if k in windows_platform_keys ]
         #  set( list([ list(v['platforms']['windows'])[0] for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if k in windows_platform_keys ]) )
         #  -> {'psh,cmd', 'pwsh', 'pwsh,psh', 'psh', 'cmd', 'psh,pwsh', 'cmd,psh'}
         #  Counter( list([ list(v['platforms']['windows'])[0] for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if k in windows_platform_keys ]) ) 
         #  -> Counter({'psh': 594, 'psh,pwsh': 19, 'cmd': 2, 'cmd,psh': 2, 'pwsh': 1, 'psh,cmd': 1, 'pwsh,psh': 1})
      psh_patterns = {'psh', 'psh,pwsh', 'pwsh', 'pwsh,psh'} # just ignore 'cmd,psh' or 'psh,cmd' for now.
      patterns_to_avoid = {'cmd', 'cmd,psh', 'psh,cmd'}
      windows_psh_keys = [k for k,v in MitreTechniqueID__caldera_ability_id__map_dict.items() if k in windows_platform_keys and \
                          set(v['platforms']['windows']).intersection(psh_patterns) != set()\
                          and set(v['platforms']['windows']).intersection(patterns_to_avoid) == set()]

      windows_keys_by_category = {
         
            "plugin": {'stockpile': windows_stockpile_keys, 
                       'atomic': windows_atomic_keys,
                       'both': windows_stockpile_keys + windows_atomic_keys },
            
            "depend": {'True': windows_depend_keys,
                       'False': windows_no_depend_keys},
            
            "powershell" : { 'True': windows_psh_keys }
      }

      # ----------------------------------------------------------------------------------------------------------------------
      # Added by JY @ 2024-3-6
      # Now get the desired keys based on 'self.plugin', 'self.platform

      selected_windows_plugin_keys = windows_keys_by_category['plugin'][self.plugin]

      selected_windows_depend_bool_keys = windows_keys_by_category['depend'][self.depend]

      selected_windows_powershell_bool_keys = windows_keys_by_category['powershell'][self.powershell]

      selected_windows_keys = set.intersection( set(selected_windows_plugin_keys), 
                                                set(selected_windows_depend_bool_keys),
                                                set(selected_windows_powershell_bool_keys) )




      # ----------------------------------------------------------------------------------------------------------------------
            # delim = "__"
            # stockpile_splitted_keys = [key.split(delim) for key in stockpile_keys]
            # atomic_splitted_keys = [key.split(delim) for key in atomic_keys]

            # stockpile_caldera_ability_ids = [x[-1] for x in stockpile_splitted_keys]
            # atomic_caldera_ability_ids = [x[-1] for x in atomic_splitted_keys]

            # # generate a dictionary in form of:
            # # e.g {T1003__credential-access__OS Credential Dumping__3c647015-ab0a-496a-8847-6ab173cd2b22" : "3c647015-ab0a-496a-8847-6ab173cd2b22"}
            # if self.plugin == "stockpile":
            #    DetailedAbilityID_AbilityID_map = dict(zip(stockpile_keys, stockpile_caldera_ability_ids))
            # elif self.plugin == "atomic":
            #    DetailedAbilityID_AbilityID_map = dict(zip(atomic_keys, atomic_caldera_ability_ids))
            # else: # both
            #    DetailedAbilityID_AbilityID_map = dict(zip(stockpile_keys + atomic_keys, 
            #                                               stockpile_caldera_ability_ids + atomic_caldera_ability_ids))

      # Added by JY @ 2024-3-6 --------------------------------------------------------------------------------------------------
      delim = "__"
      
      splitted_selected_windows_keys = [key.split(delim) for key in selected_windows_keys]

      selected_windows_keys__caldera_ability_ids = [x[-1] for x in splitted_selected_windows_keys]

      # generate a dictionary in form of:
      # e.g {T1003__credential-access__OS Credential Dumping__3c647015-ab0a-496a-8847-6ab173cd2b22" : "3c647015-ab0a-496a-8847-6ab173cd2b22"}
      DetailedAbilityID_AbilityID_map = dict(zip(selected_windows_keys, selected_windows_keys__caldera_ability_ids))
      # --------------------------------------------------------------------------------------------------


      # now generate N single-technique adversary-profiles for each technique,
      # the adversary-name will be the 'DetailedAbilityID' and '

      for DetailedAbilityID, AbilityID in DetailedAbilityID_AbilityID_map.items():  # for each technique
          
          if N == None:
               self.generate_adv_yml_file_text( technique_id = AbilityID,
                                                adversary_profile_name = DetailedAbilityID,
                                                N = None )
          
          else:             

            for trial in range(1, N+1):

               self.generate_adv_yml_file_text( technique_id = AbilityID,
                                                adversary_profile_name = DetailedAbilityID,
                                                N = trial )



   def generate_adv_yml_file_text(self, technique_id, adversary_profile_name,                                   
                                  N = None):

      ''' override "generate_adv_yml_file_text()" function for more straightforward yml file-name '''

      if N == None:
         # modified by JY @ 2024-3-6
         adversary_id = f"{self.plugin.lower()}_{self.platform}_dep{self.depend.lower()}_psh{self.powershell.lower()}__{adversary_profile_name.lower()}"
      else:
         # modified by JY @ 2024-3-6
         adversary_id = f"{self.plugin.lower()}_{self.platform}_dep{self.depend.lower()}_psh{self.powershell.lower()}__{adversary_profile_name.lower()}__trial_{N}"
      adversary_id = adversary_id.replace('/', ',').replace(':','-').replace(' ','_').replace('.','_') # to avoid error (also don't allow space)

     

      # not having '[' and ']' is very important.
      first = f"""adversary_id: {adversary_id}\nname: Single Technique Custom Adversary Profile\ndescription: {self.plugin} plugin\natomic_ordering:\n"""
      mid = f"- {technique_id} # {caldera_ability_id__MitreTechniqueID__map_dict[technique_id]}\n"
      last  ="""objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc\ntags: []"""

      custom_adversary_yml_file_text = first + mid + last

      with open( os.path.join( self.custom_adversary_profile_yml_dirpath, f'{adversary_id}.yml') ,'w') as f:    # Modified by JY @ 2023-02-27
            f.write( custom_adversary_yml_file_text )




if __name__ == "__main__":


   #############################################################################################################################
   single_techique_adversary_profile_yml_dirpath = \
   "/home/etw0/Desktop/caldera/etw/caldera/Single_Technique_Adversary_Profile__yml_files"  

   if not os.path.exists(single_techique_adversary_profile_yml_dirpath):
      raise RuntimeError(f"{single_techique_adversary_profile_yml_dirpath} doesn't exist.\nManually create it\n")

   #############################################################################################################################

   # Utilize "Custom_Adversary_Profile_Generation_Model_v1" 
   # to generate single-technique-adversary-profiles for atomic-plugin

   plugin_choice = "stockpile"

   platform_choice = "windows" # Added by JY @ 2024-3-6
   depend_choice = False # Added by JY @ 2024-3-6
   powershell_choice = True # Added by JY @ 2024-3-6

   num_trials = None
   



   gen_mod = Single_Adversary_Profile_Generation_Model(
                                                       custom_adversary_profile_yml_dirpath = \
                                                       single_techique_adversary_profile_yml_dirpath,

                                                      #  plugin = plugin_choice,
                                                      #  profile_length = 1,
                                                      #  list_of_technique_ids = None,
                                                      #  sequence_of_tactics = None,                                                        
                                                       
                                                      )

   gen_mod.generate_single_technique_adv_profiles(plugin = plugin_choice, 
                                                  platform= platform_choice, # Added by JY @ 2024-3-6
                                                  depend= depend_choice, # Added by JY @ 2024-3-6
                                                  powershell = powershell_choice, # Added by JY @ 2024-3-6
                                                  N = num_trials)