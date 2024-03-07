# JY @ 2023-11-26

'''
 For each operation file produced by caldera-server after running a adversary-profile
 ,in the specified directory (e.g. reports), 
 read it in as json file
 and parse to determine whether the ability(ies) were properly exectued (status : 0)
'''

import json
import os
import pprint
import pandas as pd
from datetime import datetime

if __name__ == "__main__":

    # SET
    reports_dirpath = "/home/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/OPERATION_REPORTS_PARSER__MINI_MACHINE_1/reports_dir" 
    result_dataframe_save_dirpath = "/home/jgwak1/tabby/SUNYIBM_ExplainableAI_2nd_Year_JY/OPERATION_REPORTS_PARSER__MINI_MACHINE_1"

    if not os.path.exists(result_dataframe_save_dirpath):
        os.makedirs(result_dataframe_save_dirpath)
    result_dataframe_save_fpath = os.path.join(result_dataframe_save_dirpath, f"Operation_Parsed_Result_DataFrame__saved_at_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.csv")

    # ---------------------------------------------------------------------------------------------------------------------------

    # pandas -- columns [ 'ability name', 'status' , 'output -- stdout', 'output -- stderr', 'output -- exitcode' , 'attack', 'name', 'description', 'command', 'ability-id', 'executor', 'platform', ]
    result_df = pd.DataFrame(columns = ["operation_fname", "adversary_id", "atomic_ordering", "number_of_abilities", 
                                        "adversary_abilities_success_rate__status_code", "adversary_abilities_success_rate__exit_code",
                                        "all_steps__status", "all_steps__output_stdout", "all_steps__output_stderr", "all_steps__output_exitcode",
                                        "all_steps__ability_id", "all_steps__ability_command", "all_steps__ability_description", "all_steps__ability_name", 
                                        "all_steps__ability_tactic_techniquename_techniqueid", "all_steps__platform", "all_steps__executor"])





    operation_fnames = os.listdir(reports_dirpath)

    for operation_fname in operation_fnames:

        print("="*30,flush= True)
        operation_fpath = os.path.join(reports_dirpath, operation_fname)

        with open( operation_fpath, 'r' ) as fp:
            operation_dict = json.load( fp )
        
        if operation_dict == None:
            new_row = { "operation_fname": operation_fname, 
                        "adversary_id": "N/A", "atomic_ordering": "N/A", "number_of_abilities": "N/A", "adversary_abilities_success_rate__status_code": "N/A",
                        "adversary_abilities_success_rate__exit_code": "N/A", "all_steps__status": "N/A", "all_steps__output_stdout": "N/A", 
                        "all_steps__output_stderr": "N/A", "all_steps__output_exitcode": "N/A", "all_steps__ability_id": "N/A", "all_steps__ability_command": "N/A", 
                        "all_steps__ability_description": "N/A", "all_steps__ability_name": "N/A", "all_steps__ability_tactic_techniquename_techniqueid": "N/A",
                        "all_steps__platform": "N/A", "all_steps__executor": "N/A", }
            result_df = pd.concat([result_df, pd.DataFrame([new_row])], ignore_index=True)             # Append the new row using concat
            continue


        adversary_id = operation_dict['adversary']['adversary_id']
        atomic_ordering = operation_dict['adversary']['atomic_ordering']
        number_of_techniques = len(atomic_ordering)

        print(f"adversary_id: {adversary_id}\n\natomic_ordering: {atomic_ordering}", flush=True)

        paw_list = list( operation_dict['steps'].keys() )  # paw is caldera-agent-id
                                                            # if paw_list >= 2 , that means there probably was a dead-agent
                                                            # dead-agent will not result in any actual steps

        for paw in paw_list:
            if len( operation_dict['steps'][paw]['steps'] ) == 0:
                # paw corresponds to a agent that was dead (invalid but was not killed for some reason)
                print(f"Invalid paw '{paw}' no steps(techniques/abilities) executed; skip", flush=True)
                continue

            if (operation_dict['steps'][paw]['steps'][0]['run'] == None) or (operation_dict['steps'][paw]['steps'][0]['pid'] == None):
                print(f"Invalid paw '{paw}' was a dead-agent ; paw-first-step--run: {operation_dict['steps'][paw]['steps'][0]['run'] } | paw-first-step--status: {operation_dict['steps'][paw]['steps'][0]['status']} | paw-first-step--pid: {operation_dict['steps'][paw]['steps'][0]['pid']}", flush= True)
                continue
                                                                                
            print(f"paw '{paw}' is a valid-agent ; paw-first-step--run: {operation_dict['steps'][paw]['steps'][0]['run'] } | paw-first-step--status: {operation_dict['steps'][paw]['steps'][0]['status']} | paw-first-step--pid: {operation_dict['steps'][paw]['steps'][0]['pid']}", flush= True)
            print("-"*30,flush= True)

            # for all steps ( step == technique(ability) ) -- for multi-technique adversaries
            all_steps__ability_id = []
            all_steps__ability_command = []
            all_steps__ability_description = []
            all_steps__ability_name = []
            all_steps__ability_tactic_techniquename_techniqueid = []

            all_steps__platform = []
            all_steps__executor = []             

            all_steps__output_stdout = []
            all_steps__output_stderr = []
            all_steps__output_exitcode = []

            all_steps__status = []


            for step_dict in operation_dict['steps'][paw]['steps']:
                # -------------------------------------------------------------------------------------
                step__ability_id = step_dict['ability_id']
                step__ability_command = step_dict['command']
                step__ability_description = step_dict['description']
                step__ability_name = step_dict['name']
                step__ability_tactic_techniquename_techniqueid = step_dict['attack']

                step__platform = step_dict['platform']
                step__executor = step_dict['executor']

                if 'output' in step_dict.keys():
                    step__output_stdout = step_dict['output']['stdout']
                    step__output_stderr = step_dict['output']['stderr']
                    step__output_exitcode = step_dict['output']['exit_code']
                else:
                    step__output_stdout = "N/A Caldera Link-Output (Possible/Valid Case)"
                    step__output_stderr = "N/A Caldera Link-Output (Possible/Valid Case)"
                    step__output_exitcode = "N/A Caldera Link-Output (Possible/Valid Case)"

                step__run = step_dict['run'] # if None, it means this step did not run properly (due to e.g. dead agent)
                step__status = step_dict['status'] # if -3, it means this step did not run properly (due to e.g. dead agent)
                step__pid = step_dict['pid'] # technique-process-id (not splunkd) ;  if None , it means this step did not run properly (due to e.g. dead agent) 

                if (step__run == None or step__pid == None): # dobule-check
                    print(f"paw '{paw}' was a dead-agent ; step__run: {step__run} | step__status: {step__status} | step__pid: {step__pid}", flush= True)
                    continue


                all_steps__ability_id.append(step__ability_id)
                all_steps__ability_command.append(step__ability_command)
                all_steps__ability_description.append(step__ability_description)
                all_steps__ability_name.append(step__ability_name)
                all_steps__ability_tactic_techniquename_techniqueid.append(step__ability_tactic_techniquename_techniqueid)

                all_steps__platform.append(step__platform)
                all_steps__executor.append(step__executor)             

                all_steps__output_stdout.append(step__output_stdout)
                all_steps__output_stderr.append(step__output_stderr)
                all_steps__output_exitcode.append(step__output_exitcode)

                all_steps__status.append(step__status)
        
                # -------------------------------------------------------------------------------------

            success_status_code = 0
            adversary_ability_success_rate__based_on_status_code = all_steps__status.count(success_status_code)/ len(all_steps__status) 

            success_excide_code = '0'
            adversary_ability_success_rate__based_on_exit_code = all_steps__output_exitcode.count(success_excide_code)/ len(all_steps__output_exitcode) 


            new_row = { "operation_fname": operation_fname, 
                        "adversary_id": adversary_id, 
                        "atomic_ordering": atomic_ordering, 
                        "number_of_abilities": number_of_techniques, 
                        "adversary_abilities_success_rate__status_code": adversary_ability_success_rate__based_on_status_code,
                        "adversary_abilities_success_rate__exit_code": adversary_ability_success_rate__based_on_exit_code,
                                                    
                        "all_steps__status": all_steps__status, 
                        "all_steps__output_stdout": all_steps__output_stdout, 
                        "all_steps__output_stderr": all_steps__output_stderr, 
                        "all_steps__output_exitcode": all_steps__output_exitcode,

                        "all_steps__ability_id": all_steps__ability_id, 
                        "all_steps__ability_command": all_steps__ability_command, 
                        "all_steps__ability_description": all_steps__ability_description, 
                        "all_steps__ability_name": all_steps__ability_name, 
                        "all_steps__ability_tactic_techniquename_techniqueid": all_steps__ability_tactic_techniquename_techniqueid,
                        "all_steps__platform": all_steps__platform, 
                        "all_steps__executor": all_steps__executor,
            }

            result_df = pd.concat([result_df, pd.DataFrame([new_row])], ignore_index=True)             # Append the new row using concat



    result_df.to_csv(result_dataframe_save_fpath)
    print(f"DONE and result-dataframe SAVED AT {result_dataframe_save_fpath}", flush = True)
