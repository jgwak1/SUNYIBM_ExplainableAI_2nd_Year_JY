import os
import json
import pandas as pd
from collections import Counter
from datetime import datetime

if __name__ == "__main__":
   # -----------------------------------------------------------------------------------------------------------------------------------------------

   # SET 
   MANIPULATED____Operation_Parsed_Result_DataFrame_csvpath = "/home/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/MITRE__APT_GROUP__TTP/MANIPULATED____Operation_Parsed_Result_DataFrame__saved_at_2024-03-10_120016.csv"
   APT_GROUP__USED_TECHNIQUES_ID_dataframe_csvpath = "/home/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/MITRE__APT_GROUP__TTP/APT_GROUP__USED_TECHNIQUES_ID.csv"
   first_run_successful_TTPs_jsonpath = "/home/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/MITRE__APT_GROUP__TTP/Successful_executed_TTPs__Technique_id__Distribution__WORKED_AT_FIRST_ROUND.json"



   # Following are based on https://docs.google.com/spreadsheets/d/1XbyFWR_zpim7Pmpz_7x4GEjR0qpNXo9Vrqu8cExscF0/edit#gid=0

   # -- tab "atomics_plugin_payloads (from several error-categ)" AND "Error-category-1 : PathToAtomicsFolder-related"
   Fixed_TTPs__payload_related__adversary_ids = [
                                                # Tab "atomics_plugin_payloads (from several error-categ)"   -- #6
                                                "atomic_windows_depfalse_pshtrue__t1553_005__defense-evasion__subvert_trust_controls-_mark-of-the-web_bypass__d2e0c0165046372fcd5e2bf910eeb477",
                                                "atomic_windows_depfalse_pshtrue__t1553_005__defense-evasion__subvert_trust_controls-_mark-of-the-web_bypass__9b3194cc656092b09f4d79ba3d3a3277",
                                                "atomic_windows_depfalse_pshtrue__t1543_003__multiple__create_or_modify_system_process-_windows_service__7030b003cc5646c7cc83410d2f057575",
                                                "atomic_windows_depfalse_pshtrue__t1553_005__defense-evasion__subvert_trust_controls-_mark-of-the-web_bypass__3c9dee6c65974cc3b4f34d0a5d1b6992",
                                                "atomic_windows_depfalse_pshtrue__t1027_004__defense-evasion__obfuscated_files_or_information-_compile_after_delivery__55b2c04e70a5711957e264b04e645e91",
                                                "atomic_windows_depfalse_pshtrue__t1555_003__credential-access__credentials_from_password_stores-_credentials_from_web_browsers__abeb340acb3e1236c6919339942e7c77",
                                                # Tab "Error-category-1 : PathToAtomicsFolder-related" # 17
                                                "atomic_windows_depfalse_pshtrue__t1547_012__multiple__boot_or_logon_autostart_execution-_print_processors__b2725f4e411b9328aa73fe54501a7564",
                                                "atomic_windows_depfalse_pshtrue__t1572__command-and-control__protocol_tunneling__45f462c09f28d5b0819af7b1ed0913e1",
                                                "atomic_windows_depfalse_pshtrue__t1071_004__command-and-control__application_layer_protocol-_dns__ce2eccff2f1de0096efa0da778a7e27c",
                                                "atomic_windows_depfalse_pshtrue__t1547_003__multiple__time_providers__23daed0787180c7f2ffbc20528570749",
                                                "atomic_windows_depfalse_pshtrue__t1547_003__multiple__time_providers__7a4867f379d79c82f217108c48bdbf33",
                                                "atomic_windows_depfalse_pshtrue__t1547_002__multiple__authentication_package__7197a8fcd7e833f42251ee3eddaa87c1",
                                                "atomic_windows_depfalse_pshtrue__t1547_001__multiple__boot_or_logon_autostart_execution-_registry_run_keys_,_startup_folder__3b631d04243ac011df9f91cd07025180",
                                                "atomic_windows_depfalse_pshtrue__t1547_001__multiple__boot_or_logon_autostart_execution-_registry_run_keys_,_startup_folder__03a127453d425bf1fd8dc9af1ed7ddce",
                                                "atomic_windows_depfalse_pshtrue__t1546_011__multiple__event_triggered_execution-_application_shimming__a967003ff25bdd94030cdd885feb25d7",
                                                "atomic_windows_depfalse_pshtrue__t1556_002__multiple__modify_authentication_process-_password_filter_dll__cc7f0eb8b9115b271eaaa42c9b6f3dca",
                                                "atomic_windows_depfalse_pshtrue__t1055__multiple__process_injection__ce67d9c1b111032ddb8a56363c854fdc",
                                                "atomic_windows_depfalse_pshtrue__t1055__multiple__process_injection__4abdd4cce7c4aa8a3804a6f5ff365514",
                                                "atomic_windows_depfalse_pshtrue__t1055_003__multiple__thread_execution_hijacking__6a64ea6e29cdb83d468a27d6f69960cb",
                                                "atomic_windows_depfalse_pshtrue__t1056_001__multiple__input_capture-_keylogging__a18a0e98b9566d92a1611a2da69b413b",
                                                "atomic_windows_depfalse_pshtrue__t1055_012__multiple__process_injection-_process_hollowing__5fef676a9954938537bd1e2191d3e9b5",
                                                "atomic_windows_depfalse_pshtrue__t1134_004__multiple__access_token_manipulation-_parent_pid_spoofing__a515bb54fd6e14b78297814875f3c73b",
                                                "atomic_windows_depfalse_pshtrue__t1134_002__multiple__create_process_with_token__163fd8a878476002c604d0fe4e32a419",
                                                ]


   # ================================================================================================================================================= 
   MANIPULATED____Operation_Parsed_Result_DataFrame = pd.read_csv(MANIPULATED____Operation_Parsed_Result_DataFrame_csvpath) # for reference if needed
   # --
   with open(first_run_successful_TTPs_jsonpath,"r") as json_fp:
      first_run_successful_TTPs_dict = json.load(json_fp)
   first_run_successful_TTPs__TechniqueID_to_Tactic__dict = { x.split(" :: ")[1] : x.split(" :: ")[0] for x in first_run_successful_TTPs_dict.keys()}
      
   # Note there can be several caldera-abilities per technique-id

   Indices_for__Fixed_TTPs__payload_related__adversary_ids = MANIPULATED____Operation_Parsed_Result_DataFrame.index[MANIPULATED____Operation_Parsed_Result_DataFrame["adversary_id"].isin(Fixed_TTPs__payload_related__adversary_ids)].tolist()
   Fixed_TTPs__payload_related__Tactics = MANIPULATED____Operation_Parsed_Result_DataFrame.loc[ Indices_for__Fixed_TTPs__payload_related__adversary_ids ]['Tactic']
   Fixed_TTPs__payload_related__TechniqueID = MANIPULATED____Operation_Parsed_Result_DataFrame.loc[ Indices_for__Fixed_TTPs__payload_related__adversary_ids ]['Technique-id']
   Fixed_TTPs__payload_related__TechniqueID_to_Tactic__dict = dict(zip(Fixed_TTPs__payload_related__TechniqueID, Fixed_TTPs__payload_related__Tactics))

   Secured_TTPs__TechniqueID_to_Tactic__dict = first_run_successful_TTPs__TechniqueID_to_Tactic__dict | Fixed_TTPs__payload_related__TechniqueID_to_Tactic__dict
   # --


   APT_GROUP__USED_TECHNIQUES_ID_dataframe = pd.read_csv(APT_GROUP__USED_TECHNIQUES_ID_dataframe_csvpath)

   APT_GROUP__SECURED_TECHNIQUES = dict()

   for APT_GROUP in APT_GROUP__USED_TECHNIQUES_ID_dataframe['APT_GROUP']:

      APT_GROUP__USED_TECHNIQUES_ID__str = list( APT_GROUP__USED_TECHNIQUES_ID_dataframe.loc[ APT_GROUP__USED_TECHNIQUES_ID_dataframe['APT_GROUP']==APT_GROUP , "USED_TECHNIQUES_ID"])[0]
      APT_GROUP__USED_TECHNIQUES_ID__list = eval( APT_GROUP__USED_TECHNIQUES_ID__str )
      APT_GROUP__USED_TECHNIQUES_ID__set = set( APT_GROUP__USED_TECHNIQUES_ID__list )

      Secured_TTPs_among_APT_GROUP_USED_TTPs = set(Secured_TTPs__TechniqueID_to_Tactic__dict.keys()).intersection(APT_GROUP__USED_TECHNIQUES_ID__set)
      Secured_TTPs_among_APT_GROUP_USED_Tactics = [ v for k,v in Secured_TTPs__TechniqueID_to_Tactic__dict.items() if k in Secured_TTPs_among_APT_GROUP_USED_TTPs ]


      APT_GROUP__SECURED_TECHNIQUES[APT_GROUP] = { 
                                                   "Secure_Rate": f"{len(Secured_TTPs_among_APT_GROUP_USED_TTPs)}/{len(APT_GROUP__USED_TECHNIQUES_ID__set)}",
                                                   "Secured_Tactics_distribution": Counter(Secured_TTPs_among_APT_GROUP_USED_Tactics),
                                                   "Secured_TTPs_among_APT_GROUP_USED_TTPs": Secured_TTPs_among_APT_GROUP_USED_TTPs,
                                                   }



      print("")
   print()

   results_savepath = os.path.join( os.path.split(APT_GROUP__USED_TECHNIQUES_ID_dataframe_csvpath)[0], 
                                   f"APT_GROUP__SECURED_TECHNIQUES__saved_at_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.csv")
   pd.DataFrame(APT_GROUP__SECURED_TECHNIQUES).T.to_csv( results_savepath )
   
   print(f"results-dataframe saved at {results_savepath}", flush=True)