import os
import json
import pandas as pd
from collections import Counter
from collections import defaultdict
from datetime import datetime

if __name__ == "__main__":
   # -----------------------------------------------------------------------------------------------------------------------------------------------

   # SET 

   Secured_TTPs_List_Info_WITHOUT_ANALYSIS__csvpath = "/home/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Synthetic_APT_Attack_sample__generation/Secured_TTPs_List_Info_WITHOUT_ANALYSIS.csv"
   # ^ https://docs.google.com/spreadsheets/d/1YJ4nPoNjZ1CVK1Rt1cDcK0shrB0Ijh7p8xUzEA-dM30/edit?usp=sharing
   
   APT_GROUP__USED_TECHNIQUES_ID_dataframe_csvpath = "/home/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/Synthetic_APT_Attack_sample__generation/APT_GROUP__USED_TECHNIQUES_ID.csv"

   # ================================================================================================================================================= 

   APT_GROUP__USED_TECHNIQUES_ID_dataframe = pd.read_csv(APT_GROUP__USED_TECHNIQUES_ID_dataframe_csvpath)
   Secured_TTPs_List_Info_WITHOUT_ANALYSIS_dataframe = pd.read_csv(Secured_TTPs_List_Info_WITHOUT_ANALYSIS__csvpath)


   # -- 
   # extract 
   Secured_TTPs_List_Info_WITHOUT_ANALYSIS_dataframe['Technique-id']
   Secured_TTPs_List_Info_WITHOUT_ANALYSIS_dataframe['adversary_id']
   Secured_TTPs_List_Info_WITHOUT_ANALYSIS_dataframe['atomic_ordering']

   dict(zip(Secured_TTPs_List_Info_WITHOUT_ANALYSIS_dataframe['atomic_ordering'], Secured_TTPs_List_Info_WITHOUT_ANALYSIS_dataframe['Technique-id']))

   Secured_TTPs__ability_id_list = [ eval(x)[0] for x in list(Secured_TTPs_List_Info_WITHOUT_ANALYSIS_dataframe['atomic_ordering']) ]
   Secured_TTPs__tactic_technique_dictlist = [ {"tactic": x.split(" :: ")[0].strip(), "technique-id": x.split(" :: ")[1].strip() } \
                                               for x in list(Secured_TTPs_List_Info_WITHOUT_ANALYSIS_dataframe['Technique-id']) ]

   Secured_TTPs__ability_id__to__tactic_technique_dict__dict =dict(zip(Secured_TTPs__ability_id_list, Secured_TTPs__tactic_technique_dictlist))

   APT_GROUP__TACTIC__SECURED_ABILITIES = dict()

   for APT_GROUP in APT_GROUP__USED_TECHNIQUES_ID_dataframe['APT_GROUP']:

      APT_GROUP__USED_TECHNIQUES_ID__str = list( APT_GROUP__USED_TECHNIQUES_ID_dataframe.loc[ APT_GROUP__USED_TECHNIQUES_ID_dataframe['APT_GROUP']==APT_GROUP , "USED_TECHNIQUES_ID"])[0]
      APT_GROUP__USED_TECHNIQUES_ID__list = eval( APT_GROUP__USED_TECHNIQUES_ID__str )
      APT_GROUP__USED_TECHNIQUES_ID__set = set( APT_GROUP__USED_TECHNIQUES_ID__list )


      APT_GROUP_Secured_TTPs__Techniques_set = APT_GROUP__USED_TECHNIQUES_ID__set.intersection( { v['technique-id'] for k,v in Secured_TTPs__ability_id__to__tactic_technique_dict__dict.items() } )
      # Secured_TTPs_among_APT_GROUP_USED_Tactics = [ v for k,v in Secured_TTPs__TechniqueID_to_Tactic__dict.items() if k in Secured_TTPs_among_APT_GROUP_USED_TTPs ]

      # JY @ 2024-04-08 : 
      #     TODO -- Desired output is mapping from 'APT-Group' to 'Tactic' to 'secured-techniques'
      todo = True

      APT_GROUP__TACTIC__SECURED_ABILITIES[APT_GROUP] = defaultdict(list)

      for ability_id, tactic_technique_dict in Secured_TTPs__ability_id__to__tactic_technique_dict__dict.items():
         
         tactic = tactic_technique_dict['tactic']
         technique_id = tactic_technique_dict['technique-id']

         if technique_id in APT_GROUP_Secured_TTPs__Techniques_set:
            APT_GROUP__TACTIC__SECURED_ABILITIES[APT_GROUP][tactic].append(ability_id)

      # APT_GROUP__TACTIC__SECURED_TECHNIQUES[APT_GROUP] = { 
      #                                              "Secure_Rate": f"{len(Secured_TTPs_among_APT_GROUP_USED_TTPs)}/{len(APT_GROUP__USED_TECHNIQUES_ID__set)}",
      #                                              "Secured_Tactics_distribution": Counter(Secured_TTPs_among_APT_GROUP_USED_Tactics),
      #                                              "Secured_TTPs_among_APT_GROUP_USED_TTPs": Secured_TTPs_among_APT_GROUP_USED_TTPs,
      #                                              }



      print("")
   print()

   results_savepath = os.path.join( os.path.split(APT_GROUP__USED_TECHNIQUES_ID_dataframe_csvpath)[0], 
                                   f"APT_GROUP__TACTIC__SECURED_ABILITIES__saved_at_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json")

   with open(results_savepath, "w") as json_fp:
      json.dump(APT_GROUP__TACTIC__SECURED_ABILITIES, json_fp)
   
   print(f"result-dict saved at {results_savepath}", flush=True)