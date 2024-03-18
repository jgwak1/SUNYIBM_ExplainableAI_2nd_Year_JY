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
                                                # Tab "Error-category-1 : PathToAtomicsFolder-related" # 18
                                                "atomic_windows_depfalse_pshtrue__t1547_001__multiple__boot_or_logon_autostart_execution-_registry_run_keys_,_startup_folder__fef50b36806647cb5a5511ae48f7e56f",
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

                                                # Tab "Error-category-1-2 : ExternalPayloads
                                                "atomic_windows_depfalse_pshtrue__t1070_006__defense-evasion__indicator_removal_on_host-_timestomp__f1dcadde207fafe338ae3eb48805f23c",
                                                "atomic_windows_depfalse_pshtrue__t1070_006__defense-evasion__indicator_removal_on_host-_timestomp__68ce066d07960123ccd981dd8c38a7c1",
                                                "atomic_windows_depfalse_pshtrue__t1070_006__defense-evasion__indicator_removal_on_host-_timestomp__1f2da2639fcd636ef1c7ead72de4469f",
                                                "atomic_windows_depfalse_pshtrue__t1539__credential-access__steal_web_session_cookie__126aaf80c6a232eaf08dcef3163d4aed",
                                                "atomic_windows_depfalse_pshtrue__t1070_006__defense-evasion__indicator_removal_on_host-_timestomp__08a146a382df6fea9fa2275073e9d245",
                                                "atomic_windows_depfalse_pshtrue__t1485__impact__data_destruction__b74b60096fb49650e27e470047a2b9c9",
                                                "atomic_windows_depfalse_pshtrue__t1187__credential-access__forced_authentication__608b7021a5b8369e9fd858feba6f5611",
                                                "atomic_windows_depfalse_pshtrue__t1003_002__credential-access__os_credential_dumping-_security_account_manager__3bcfa369fd1f214e4d05944228eeb212",
                                                "atomic_windows_depfalse_pshtrue__t1134_001__multiple__access_token_manipulation-_token_impersonation,theft__81289b3d78d06c14b816f7644b1d9f8b",
                                                "atomic_windows_depfalse_pshtrue__t1083__discovery__file_and_directory_discovery__abc280f400f218aa1f4d5efe3c9e8228",


                                                # Tab "Error-category-2 : Program not installed issue" (#6)
                                                "atomic_windows_depfalse_pshtrue__t1555__credential-access__credentials_from_password_stores__f6867f2b9b1b3c2eb733ad7ce7438f04",
                                                "atomic_windows_depfalse_pshtrue__t1133__multiple__external_remote_services__ff4e1ea516f781a6ef93323ba9dfac0a",
                                                "atomic_windows_depfalse_pshtrue__t1555_003__credential-access__credentials_from_password_stores-_credentials_from_web_browsers__679ef375ad2b361965500392419d084c",
                                                "atomic_windows_depfalse_pshtrue__t1219__command-and-control__remote_access_software__820a346b2b676b51338c1170b675f76b",
                                                "atomic_windows_depfalse_pshtrue__t1555_003__credential-access__credentials_from_password_stores-_credentials_from_web_browsers__1cca72410c2849070d833700fcc30c59",
                                                "atomic_windows_depfalse_pshtrue__t1003_001__credential-access__os_credential_dumping-_lsass_memory__8e01631039faf6a9a84df376bf9ad0f1",
                                                # Tab "Error-category-3: Cannot find path <FILEorFolder> non_payload" (#4)
                                                "atomic_windows_depfalse_pshtrue__t1553_005__defense-evasion__subvert_trust_controls-_mark-of-the-web_bypass__7f0f5471543a6f188b0fbdc436c49fd9",
                                                "atomic_windows_depfalse_pshtrue__t1070_004__defense-evasion__indicator_removal_on_host-_file_deletion__04858322bc6cd08282f2ce96cab5ee7c",
                                                "atomic_windows_depfalse_pshtrue__t1003__credential-access__os_credential_dumping__f6c693da77b8824b3c52ba3b6ca0bf88",
                                                "atomic_windows_depfalse_pshtrue__t1003__credential-access__os_credential_dumping__2cc37a6cf2f1acdeaa6a6638016444d1",

                                                # Tab "Error-category-4: Cannot find path <REGISTRY>" (#5)
                                                "stockpile_windows_depfalse_pshtrue__t1562_001__defense-evasion__impair_defenses-_disable_or_modify_tools__3864fd22-5c63-41c9-bdbc-a66b5ffa3f5e",
                                                "atomic_windows_depfalse_pshtrue__t1562_001__defense-evasion__impair_defenses-_disable_or_modify_tools__cb6e6c7e18aba2207c696368f8edb23a",
                                                "atomic_windows_depfalse_pshtrue__t1562_001__defense-evasion__impair_defenses-_disable_or_modify_tools__4df316c222125fe7372723c5b3434977",
                                                "atomic_windows_depfalse_pshtrue__t1547_014__multiple__active_setup__7ad5840a79f3259965fa28835dda93c4",
                                                "atomic_windows_depfalse_pshtrue__t1112__defense-evasion__modify_registry__86993ae14d75a6da421c0d98c3facd61",
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