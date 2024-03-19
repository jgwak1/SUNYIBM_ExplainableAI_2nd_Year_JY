#!/usr/bin/env python3

# Importing libraries
import socket
import sys
import os
import time
import pickle
import random
import time
import subprocess

from caldera import random_ab
from caldera import generate_adv
from caldera import control_server
from caldera import delete_operation
from caldera import create_operation
from caldera import delete_agent




# Added by JY @ 2023-02-28
import datetime 

# Added by JY @ 2023-10-25 : Try to get the operation-report using this.
# https://github.com/mitre/caldera/blob/e6d712bd19107ad8698c3810993bf778d69abe03/tests/api/v2/handlers/test_operations_api.py#L45
# sys.path.append("/home/priti/Desktop/caldera/")
# from app.utility.base_service import BaseService
# from app.api.v2.managers.operation_api_manager import * 
# operation_api_manager = OperationApiManager( BaseService.get_service('data_svc') )
# operation_api_manager.get_operation_report(operation_id=, access=, output=)

VM_IP = '192.168.122.229'     # JY:  mini-machine-1 (Q22) ip-address    
OurIp = 'localhost'
        
    
def interact_with_VM_for_logging( p, activity_wait_seconds, adversary_id, post_activity_wait_seconds, store_name= None):
    
    '''
    [Added by JY @ 2023-02-27 for JY's better understanding]
    Start to record
    https://docs.google.com/document/d/1Z7dx2a--M2dUrdub-J-ljwCMSjShgLe1rG4ALChi4ic/edit
    '''
    print (f'start : {adversary_id}', flush=True) 

    # added by JY @ 2024-1-14: just for debugging -- comment this ou tlater
    #created_operation_info_dict = create_operation.create_operation( adversary_id = adversary_id ) 

    #-----------------------------------------------------------------------------------------------------------------------
    # 1. Send message (<adversary_id>) to VM

    s = socket.socket() # Now we can create socket object 
    SEND_PORT = 9900     # Lets choose one port and connect to that port
    s.connect((VM_IP, SEND_PORT))   # Lets connect to that port where socket at VM side may be waiting
    
    # https://www.cyberciti.biz/faq/how-to-check-open-ports-in-linux-using-the-cli/
    # sudo netstat -tulpn | grep LISTEN

    # message_to_send = f"{adversary_id}__postwaitsecs_{post_activity_wait_seconds}"

    # JY @ 2024-2-26: "Additional Logstash filters"
    # message_to_send = f"{adversary_id}__postwaitsecs_{post_activity_wait_seconds}__Added_Logstash_Filters"
    # message_to_send = f"{adversary_id}__postwaitsecs_{post_activity_wait_seconds}__20240227"

    # message_to_send = f"{adversary_id}__postwaitsecs_{post_activity_wait_seconds}__splunkd_descendent_Logstash_Filters__20240304"
    message_to_send = f"{adversary_id}__attacksecs{activity_wait_seconds}_postwaitsecs{post_activity_wait_seconds}"


    # s.send(message_to_send.to_bytes(2,'big'))   # send 함수는 데이터를 해당 소켓으로 보내는 함수이고
    s.send(message_to_send.encode('utf-8'))    
    s.close()  # Close the connection from client side
    
    #-----------------------------------------------------------------------------------------------------------------------    
    # 2. Wait and receive message of "started__logstash__silkservice__caldera_agent" from VM
    s = socket.socket()     # Now we can create socket object
    PORT = 1100             # Lets choose one port and start listening on that port
    print(f"\n HOST-socket is listening on port : {PORT}\n", flush = True)
    s.bind(('', PORT)) # Now we need to bind socket to the above port 
    s.listen(10)    # Now we will put the binded socket listening mode

    message_to_receive = None 
    while True: # We do not know when client will contact; so should be listening continously  
        conn, addr = s.accept()    # Now we can establish connection with client
        message_to_receive = conn.recv(1024).decode()
        conn.close()
        print("\n HOST-socket closed the connection\n", flush=True)
        break

    if message_to_receive == "started__logstash__silkservice__caldera_agent":
        print(f"\n From VM, received message: {message_to_receive}\n", flush = True )
    else:
        raise ValueError(f"Value-Error with received message: {message_to_receive}")
 
    s.close()  
    time.sleep(5)
    #-----------------------------------------------------------------------------------------------------------------------        
    # 3. Create operations with API (it will start to run)
    print(f'Start Attack (create_operation) : {adversary_id}', flush = True)
    
    ''' JY @ 2023-10-21: Adversary yml file should be placed in /home/etw0/Desktop/caldera/data/adversaries'''
    created_operation_info_dict = create_operation.create_operation( adversary_id = adversary_id, post_activity_wait_seconds = post_activity_wait_seconds ) 
    
    # /home/jgwak1/tools__Copied_from_home_zhsu1_tools/etw/caldera/create_operation.py
                                            # def create_operation():
                                            #     print('do not change adversary id')
                                            #     cmd = 'curl -X PUT -H "KEY:ADMIN123" http://localhost:8888/api/rest -d '+"'{"+'"index":"operations", "name":"testop1","adversary_id":"b176f4b1-a582-4774-b6f6-46a2e11480af" '+"}'"
                                            #     print (cmd)
                                            #     os.system(cmd)    
    #-----------------------------------------------------------------------------------------------------------------------        
    # 4. *For now, wait for "record time" during attack.
    #                   
    #     ^ Better way would be to capture the operation-termination,
    #       (Need to find a way to do that; maybe using operation-id)
    #       Then, tell the VM that operation is terminated, so stop log-collection.
    #   
    time.sleep(activity_wait_seconds)
    print(f'end attack for {adversary_id}, as activity_wait_seconds {activity_wait_seconds}s elapsed.', flush = True)
    #-----------------------------------------------------------------------------------------------------------------------        
    # 5. Send message ("terminate__logstash__silkservice") to VM

    s = socket.socket() # Now we can create socket object 
    SEND_PORT = 9100     # Lets choose one port and connect to that port
    try:
        s.connect((VM_IP, SEND_PORT))   # Lets connect to that port where socket at VM side may be waiting
    except:
        raise RuntimeError(f"Could not connect to {VM_IP} :: {SEND_PORT}")

    #message_to_send = "terminate__logstash__silkservice"

    # Modified by JY @ 2024-1-14
    #post_activity_wait_seconds = 3600
    message_to_send = str( post_activity_wait_seconds )

    # s.send(message_to_send.to_bytes(2,'big'))   # send 함수는 데이터를 해당 소켓으로 보내는 함수이고

    s.send( message_to_send.encode('utf-8') )   # send 함수는 데이터를 해당 소켓으로 보내는 함수이고
    s.close()  # Close the connection from client side

    #-----------------------------------------------------------------------------------------------------------------------        
    # 6. Shutdown caldera server
    control_server.shutdown_process(p)      # /home/jgwak1/tools__Copied_from_home_zhsu1_tools/etw/caldera/control_server.py

                                            # def shutdown_process(p):
                                            #     p.terminate()

    #-----------------------------------------------------------------------------------------------------------------------        
    # 7. Wait and receive message of "post_activity_wait_seconds__is_over" from VM
    s = socket.socket()     # Now we can create socket object
    PORT = 9998             # Lets choose one port and start listening on that port
    print(f"\n HOST-socket is listening on port (to wait message from VM that post-activity-wait-seconds is over): {PORT}\n", flush = True)
    s.bind(('', PORT)) # Now we need to bind socket to the above port 
    s.listen(10)    # Now we will put the binded socket listening mode

    message_to_receive = None 
    while True: # We do not know when client will contact; so should be listening continously  
        conn, addr = s.accept()    # Now we can establish connection with client
        message_to_receive = conn.recv(1024).decode()
        conn.close()
        print("\n HOST-socket closed the connection\n", flush=True)
        break

    if message_to_receive == "post_activity_wait_seconds_is_over__logstash_silkservice_terminated":
        print(f"\n From VM, received message: {message_to_receive}\n", flush = True )
    else:
        raise ValueError(f"Value-Error with received message: {message_to_receive}")
 
    s.close()  
    time.sleep(5)
 


def get_cmd():
    ret = []
    all_hex = pickle.load(open('no_depend.pkl','rb'))
    l = random.sample(all_hex,5)
    print (l)
    for i in l:

        tmp ="""curl -H "KEY:ADMIN123" -X POST localhost:8888/plugin/access/exploit -d '{"paw":"qiydwj","ability_id":" """
        tmp1 =""" ","obfuscator":"plain-text"}'"""
        tmp = tmp[:-1] + i + tmp1[1:]

        ret.append(tmp)
    return ret



def run_caldera():
    
    ''' 
    [Added by JY @ 2023-02-27 for JY's better understanding]
    
    "run_caldera()" starts the Caldera server, and waits to start, and returns process-info "pid"
    
    > https://docs.google.com/document/d/1Z7dx2a--M2dUrdub-J-ljwCMSjShgLe1rG4ALChi4ic/edit
    
    > (For Terminology)
    > https://caldera.readthedocs.io/en/2.8.0/Learning-the-terminology.html#what-is-an-operation   
    '''

    #-----------------------------------------------------------------------------------------------------------------------
    # 1. Get abilities (JY: 이때 ability라 함은 “Abilities” is just atomic “(benign) commands” as “whoami”. )
    # print ('get ablities')
    # ablities = random_ab.random_ab(7)           # /home/jgwak1/tools__Copied_from_home_zhsu1_tools/etw/caldera/random_ab.py

                                                # def get_avaliable_ab(fact):
                                                # a = pickle.load(open('ab_list.pkl','rb'))
                                                # av = []
                                                # for i in a:
                                                #     if i[1] in fact:
                                                #         av.append(i)
                                                # return av

                                                # def random_ab(n):
                                                #     l = []

                                                #     fact = ['None']

                                                #     # load all abilities 

                                                #     a = pickle.load(open('ab_list.pkl','rb'))
                                                #     while (n>0):
                                                        
                                                #         # get avaliable ability
                                                #         all_ab = get_avaliable_ab(fact)
                                                        
                                                #         # random one
                                                #         random_ab = random.choice(all_ab)
                                                #         l.append(random_ab)
                                                        
                                                #         # update fact
                                                #         if not random_ab[2] in fact:
                                                #             fact.append(random_ab[2])
                                                #         n -= 1
                                                #     return l


    # print("Get JY's File/Registry Related Abilities", flush= True)
    # ablities = JoonYoung_FileRegistry_Abilities()


    #-----------------------------------------------------------------------------------------------------------------------
    # 2. Generate adversiries (JY: “Adversaries” is just sequences)
    #    and copy adversiery into caldera data directory
    # print ('generate adversiries')
    # generate_adv.generate_adv(ablities)     # /home/jgwak1/tools__Copied_from_home_zhsu1_tools/etw/caldera/generate_adv.py

                                            # def generate_adv(ab_list):
                                            #     # get random ablities 
                                            #     ab = ab_list
                                            #     text = """adversary_id: b176f4b1-a582-4774-b6f6-46a2e11480af
                                            # name: random
                                            # description: random 5 abilities
                                            # atomic_ordering:
                                            # - {}
                                            # - {}
                                            # - {}
                                            # - {}
                                            # - {}
                                            # objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
                                            # tags: []""".format(ab[0][0],ab[1][0],ab[2][0],ab[3][0],ab[4][0])

                                            #     with open('b176f4b1-a582-4774-b6f6-46a2e11480af.yml','w') as f:
                                            #         f.write(text)
                                            #     shutil.copy('b176f4b1-a582-4774-b6f6-46a2e11480af.yml','/home/zshu1/tools/caldera/data/adversaries/')


    #-----------------------------------------------------------------------------------------------------------------------
    # 3. Start caldera server, and Remove all operations        
    # 
    #    More specifically,
    #       Start caldera server and get all existing operations id (store in  ‘/home/zshu1/tools/etw/tmp/operations.pkl’)
    #       Remove all existing operations by API
    # 
    # (JY: “Operations” is to actually run “Adversaries” (Attack))
    print ('wait to start caldera')
    p =  control_server.start_process()     # /home/jgwak1/tools__Copied_from_home_zhsu1_tools/etw/caldera/control_server.py

                                            # def start_process():
                                            # os.chdir('/home/zshu1/tools/caldera/')
                                            # cmd = ['python3','/home/priti/Desktop/caldera/server.py','--insecure']   
                                            # p = subprocess.Popen(cmd)
                                            # return p
    
    # time.sleep(60) # need to wait some time -- make sue 0.0.0.0:8888 is LISTENING with python service (i.e. caldera server starting is done), before moving on next. (netstat -tlnp)
    # Added by JY @ 2023-12-18  -- Works as intended
    while True: 
        netstat_result = subprocess.run(['netstat', '-tlnp'], stdout = subprocess.PIPE, stderr=subprocess.PIPE)
        decoded_netstat_result = netstat_result.stdout.decode()
        if '8888' in decoded_netstat_result: # we need to wait until caldera server process completely starts (i.e. 8888 port LISTENING)
            break
 
    #   get all existing operations id (to remove) 
    print ('delete exist operations')
    # op_ids = pickle.load(open('/home/zshu1/tools/etw/tmp/operations.pkl','rb'))
    op_ids = pickle.load(open('/home/etw0/Desktop/caldera/etw/tmp/operations.pkl','rb'))    
    #   Remove all existing operations by API
    delete_operation.delete_operations(op_ids)      # /home/jgwak1/tools__Copied_from_home_zhsu1_tools/etw/caldera/delete_operation.py

                                                    # def delete_operation(op_id):
                                                    #     cmd = 'curl -H "KEY:ADMIN123" -X DELETE http://localhost:8888/api/rest -d '+"'{"+'"index":"operations","id":"{}"'.format(op_id)+"}'"
                                                    #     os.system(cmd)

                                                    # def delete_operations(op_list):
                                                    #     for i in op_list:
                                                    #         delete_operation(i)

    #-----------------------------------------------------------------------------------------------------------------------
    print ('\ndone start caldera')
    
    
    return p   # Return the PID of the "Caldera Server Process"






def procedure( pid, activity_wait_seconds, adversary_id, post_activity_wait_seconds, snapshot_name, vm_name ): 

    ''' 
    [Added by JY @ 2023-02-27 for JY's better understanding]

    "receive_sample()" is to start collecting ETW logs. 
    ‘pid’ ("Caldera Server Process PID") is used to shut down caldera after finishing the attack.  
    ‘activity_wait_seconds’ control how long we want to record.


    https://docs.google.com/document/d/1Z7dx2a--M2dUrdub-J-ljwCMSjShgLe1rG4ALChi4ic/edit 
    '''

    #-----------------------------------------------------------------------------------------------------------------------
    # 1. Set up store dir (store sample in tmp)
    #store_dir = '/home/zshu1/tools/etw/tmp'
    store_dir = "/home/etw/Desktop/caldera/etw/tmp"  # Modified by JY @ 2023-02-27
    
    #-----------------------------------------------------------------------------------------------------------------------
    # 3. Delete the existing agent(it's outdated) from caldera sever
    # reset agent 
    print ('remove all agents on caldera-server -- sometimes works, sometime doesnt work for some reason which could be problem (2023-12-20)')
    time.sleep(10)

    # delete_agent.delete_agent()     # /home/jgwak1/tools__Copied_from_home_zhsu1_tools/etw/caldera/delete_agent.py

    #                                 # def delete_agent():
    #                                 #     cmd = 'curl -H "KEY:ADMIN123" -X DELETE http://localhost:8888/api/rest -d '+"'{"+'"index":"agents","paw":"qiydwj"'+"}'"
    #                                 #     print (cmd)
    #                                 #     os.system(cmd)

    # Added by JY @ 2023-03-07

    # JY @ 2023-11-08 : Delete all agents does not work perfectly for some reason.
    #                   sometimes works, sometimes not
    delete_agent.delete_all_agents()    # "delete_all_agents" is implemented by JY @ 2023-03-07.
                                        # # Added by JY @ 2023-03-07:
                                        # #   Motivation is the existing 'delete_agent()' which Zhan implemented, only targets a particular agent of paw == "qiydwj"
                                        # #   However, that particular agent is something Zhan dealt with before I started working on this. Thus, such agent doesn't exist in my context.
                                        # #   Instead, I am in a context of, having to delete the caldera-agent from the previous run 
                                        # #   (in terms of geenerating caltera-dattack event logs in a for loop, with caldera built-in adversary-profile yml files - from stockpile)
                                        # #   In this context, I do not have access to the specific paw of the existing agent, 
                                        # #   so I should use the following, which delete all existing agents (that we don't need) on caldera-server. 
                                        # def delete_all_agents():
                                        #     cmd = 'curl -H "KEY:ADMIN123" -X DELETE http://localhost:8888/api/rest -d '+"'{"+'"index":"agents"'+"}'"
                                        #     print (cmd)
                                        #     os.system(cmd)                            

    time.sleep(10)

    #-----------------------------------------------------------------------------------------------------------------------
    # 2. Reset VM (wait 40 sec)
    # reset vm and wait 40 seconds
    
    #os.system('virsh -c qemu:///system snapshot-revert win10_2 ready')
    # Added by JY @ 2023-03-01: The VM I am using is "win10" and newly created a snapshot ""
    # vm_name = "win10"
    # #snapshot_name = "snapshot_caldera_custom_adv_profile_20231220_updated_15"
    # # snapshot_name = "snapshot_caldera_custom_adv_profile_20240115"
    # # snapshot_name = "snapshot_caldera_custom_adv_profile_20240226_v2"
    # # snapshot_name = "snapshot_caldera_adv_profile_20240229_v6"
    # #snapshot_name = "snapshot_caldera_custom_adv_profile__filter_Silkservice_EventName_v2"
    
    # snapshot_name = "snapshot_caldera_custom_adv_profile__splunkd_descendents_non_concurrent_v2" # this one is the good one

    #revert_give_time = 300 # this may not be necessary, but makes it less error-prone.
    start_revert = datetime.datetime.now()
    print (f'\nreverting to snapshot {snapshot_name} -- started at {str(start_revert)}', flush=True)
    os.system(f'virsh -c qemu:///system snapshot-revert {vm_name} {snapshot_name}') # works (confirmed at 2023-03-01)
    #time.sleep(revert_give_time) # -- this results in absolute waste of time
    end_revert = datetime.datetime.now()
    print (f'\nreverted to snapshot {snapshot_name} -- ended at {str(end_revert)} -- took {str(end_revert-start_revert)}', flush=True)    
    print ('one sample sleep 30 sec to reset', flush=True)
    time.sleep(30)


    # JY 질문: 아래 부분은 어딨냐?
    # 4. Wait 30 sec for caldera agent to get the connection with caldera server.


    print(f'start to record --  activity_wait_seconds: {activity_wait_seconds} s', flush= True)
    #-----------------------------------------------------------------------------------------------------------------------
    # 5. Start to record
    # create a server to receive samples 
    interact_with_VM_for_logging(pid, activity_wait_seconds, adversary_id , post_activity_wait_seconds = post_activity_wait_seconds )
    print ('finish')






def main():


    ''' TODO @ 2024-1-15: ArgParser for 'adversary-id' '''


    # TODO:
    # 1. Debugger 로 Run해봐 (Connection-refused 고쳐 )
    #   > https://stackoverflow.com/questions/41027340/curl-connection-refused
    #   > netstat -tulpn
    #   > netstat -ln
    #   > You have to start the server first, before using curl. On 8/10 occasions that error message arises from not starting the server initially.
    # 2. Caldera website에서 adversary들 다운로드해봐.

    # SET 
    loop = True

    if loop == False:
        post_activity_wait_seconds = 5

    activity_wait_seconds = 600 # 600
    vm_name = "win10"
    #snapshot_name = "snapshot_caldera_custom_adv_profile__filter_Silkservice_EventName_v2"    
    # snapshot_name = "snapshot_caldera_custom_adv_profile_splunkd_descendents_non_concurrent_v3" # this one is the good one    
    # snapshot_name = "snapshot_caldera_custom_adv_profile_splunkd_descendents_non_concurrent_v4" # tried to further handle time-sync issue  
    #snapshot_name = "snapshot_caldera_custom_adv_profile_splunkd_descendents_non_concurrent_v5" # 2024-3-8 (forced syncronization taskschedulor -run)  

    # snapshot_name = "snapshot_caldera_custom_adv_profile_splunkd_descendents_non_concurrent_v6" # 2024-3-10 (same as v5 except for date)
    # snapshot_name = "snapshot_caldera_custom_adv_profile_splunkd_descendents_non_concurrent_timesync_reg" # time resync reg MaxNeg/PosPhaseCorrection 0xffffffff -- Not effective.
    # snapshot_name = "snapshot_caldera_custom_adv_profile_splunkd_descendents_non_concurrent_timesync_reg_v2"
    # snapshot_name = "snapshot_caldera_custom_adv_profile_splunkd_descendents_non_concurrent_timesync_reg_v3" # time resync reg MaxNeg/PosPhaseCorrection 0xffffffff -- Not effective.

    # snapshot_name = "snapshot_caldera_custom_adv_profile_splunkd_descendents_non_concurrent_timesync_reg_v4"

    #snapshot_name = "snapshot_caldera__splunkd_tree_non_concurrent__timesync_reg__installed_some__v3"

    snapshot_name = "snapshot_caldera__splunkd_tree_non_concurrent__timesync_reg__installed_apps__inetserv__v4"

    if loop == False:

        start = datetime.datetime.now()

        # get commmand 
        pid = run_caldera() # "run_caldera()" starts the Caldera server, and waits to start, and returns caldera-server process-info "pid"

        # adversary-profile should be stored in "/home/priti/Desktop/caldera/data/adversaries"
        # adversary_id = "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-23-20_09_50"
        # adversary_id = "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-23-20_09_43"

        # adversary_id = "custom_adversary_profile__None__None__stockpile__2023-10-23-20_10_55"

        # adversary_id = "atomic__t1003__credential-access__os_credential_dumping__2cc37a6cf2f1acdeaa6a6638016444d1__trial_1"

        #adversary_id = "joonyoung_single_technique_profile_for_network_event_invoking_custom_technique"
        # adversary_id = "joonyoung_single_technique_profile_for_file_event_invoking_custom_technique"
        # adversary_id = "joonyoung_single_technique_profile_for_registry_event_invoking_custom_technique"

        # adversary_id = "joonyoung_multi_technique_profile_for_fileregnet_event_custom_techniques_nine"

        # adversary_id = "atomic__t1003__credential-access__os_credential_dumping__2cc37a6cf2f1acdeaa6a6638016444d1__trial_1"

        # adversary_id = "atomic_windows_depfalse_pshtrue__t1134_004__multiple__access_token_manipulation-_parent_pid_spoofing__a515bb54fd6e14b78297814875f3c73b"

        procedure( pid, activity_wait_seconds, adversary_id, post_activity_wait_seconds, snapshot_name, vm_name )   
                                # "receive_sample()" is to start collecting ETW logs. 
                                # ‘pid’ ("Caldera Server Process PID") is used to shut down caldera after finishing the attack.  
                                # ‘record_time’ control how long we want to record.

        end = datetime.datetime.now()

        print(f"Elapsed-Time for {adversary_id}: {str(end-start)}", flush= True)

    else: # doing it in a loop
        # 
        # SET 
        my_adversaries_dir = "/home/etw0/Desktop/caldera/data/adversaries"
        operation_reports_savedir = "/home/etw0/Desktop/caldera/etw/operation_reports_savedir/reports"
        adversary_id_patterns_to_skip = ["joonyoung_", "trial_1", "trial_2", "trial_3", "trial_4", "trial_5"] 
        adversary_ids_to_explicitly_skip = []

        loop_execution_progress_log_fname = f"MAIN_LOOP_EXECUTION_PROGRESS_LOG__started_@_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.txt"

        loop_execution_progress_log_dirpath = os.path.split(operation_reports_savedir)[0]
        loop_execution_progress_log_fpath = os.path.join(loop_execution_progress_log_dirpath, loop_execution_progress_log_fname)
        # Added by JY @ 2024-3-18
        with open( loop_execution_progress_log_fpath,"a") as f:
            f.write(f"\nVM-NAME: {vm_name} | SNAPSHOT-NAME: {snapshot_name}\n")


        # --------------------------

        # adversary_yml_fnames = [x for x in os.listdir(my_adversaries_dir) if x.endswith(".yml")]
        # adversary_ids = [ x.removesuffix(".yml") for x in adversary_yml_fnames]

        # from TTP_adversary_ids_to_rerun__2024_03_10 import TTP_adversary_ids_to_rerun__2024_03_10 -- DONE
        #from Treatment_applied_TTP_adversary_ids__2024_03_12 import Treatment_applied_TTP_adversary_ids__2024_03_12
        #adversary_ids = Treatment_applied_TTP_adversary_ids__2024_03_12


        # JY @ 2024-03-18:  https://docs.google.com/spreadsheets/d/1cLlNZhshOT8QvMa1KcCu_xY24_tTG5HZopNpZ_eir3Q/edit#gid=1239105720
        import pandas as pd
        Secured_TTPs_Log_collection_df = pd.read_csv("/home/etw0/Desktop/caldera/etw/Secured TTPs Log-collection.csv")

        mini_machine_1_collect_Indices = Secured_TTPs_Log_collection_df["COLLECT_MACHINE"] == "mini-machine-1"        
        # adversary_ids = 

        
        adversary_ids__POST_ACTIVITY_WAIT_MINUTES__dict =\
                 dict( zip(Secured_TTPs_Log_collection_df[ mini_machine_1_collect_Indices ]["adversary_id"],
                           Secured_TTPs_Log_collection_df[ mini_machine_1_collect_Indices ]["POST-ACTIVITY-WAIT-MINUTES"]))
        

        # -------------------

        already_operation_generated_reports_fnames= [ x for x in os.listdir(operation_reports_savedir) if x.startswith("operation_") ]
        already_operation_generated_adversary_ids = [ x[:x.rfind("__SAVED")].removeprefix("operation__") for x in already_operation_generated_reports_fnames]
        # modified by JY @ 2024-03-18
        adversary_ids_to_generate = [ x for x in adversary_ids__POST_ACTIVITY_WAIT_MINUTES__dict \
                                        if ( x not in already_operation_generated_adversary_ids )\
                                             and ( x not in adversary_ids_to_explicitly_skip )\
                                             and ( not any( pattern in x for pattern in adversary_id_patterns_to_skip ) )  ]
        adversary_ids_to_generate = sorted(adversary_ids_to_generate)   # JY @ 2023-11-07: Sort it so that same technique's trial 1,2,3,4,5 are done.

        # modified by JY @ 2024-03-18
        TO_GENERATE__adversary_ids__POST_ACTIVITY_WAIT_MINUTES__dict =\
            {k: v for k,v in adversary_ids__POST_ACTIVITY_WAIT_MINUTES__dict.items() if k in adversary_ids_to_generate }

        # TTP -specific POST-ACTIVITY-WAIT-TIMES
        # -- https://docs.google.com/spreadsheets/d/1cLlNZhshOT8QvMa1KcCu_xY24_tTG5HZopNpZ_eir3Q/edit#gid=1239105720



        cnt=0
        for adversary_id, post_activity_wait_minutes in TO_GENERATE__adversary_ids__POST_ACTIVITY_WAIT_MINUTES__dict.items():
            cnt+=1
            
            # Added by JY @ 2024-3-18
            post_activity_wait_seconds = post_activity_wait_minutes * 60
            

            time.sleep(5) # wait things to wrap up for just in case
            
            print(f"\nStart {cnt}/{len(adversary_ids_to_generate)} : {adversary_id}  @ {datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}\n", flush=True)
            with open( loop_execution_progress_log_fpath,"a") as f:
                f.write(f"\nStart {cnt}/{len(adversary_ids_to_generate)} : '{adversary_id}' with 'post_activity_wait_seconds': {post_activity_wait_seconds} seconds @ {datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}\n")

            start = datetime.datetime.now()            
            pid = run_caldera() 
            procedure( pid, activity_wait_seconds, adversary_id, post_activity_wait_seconds, snapshot_name, vm_name ) 
            end = datetime.datetime.now()

            print(f"Elapsed-Time for {adversary_id}: {str(end-start)} -- finished {cnt}/{len(adversary_ids_to_generate)}  @ {datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}", 
                    flush= True)
            with open(loop_execution_progress_log_fpath,"a") as f:
                f.write(f"Elapsed-Time for {adversary_id}: {str(end-start)} -- finished {cnt}/{len(adversary_ids_to_generate)}  @ {datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}\n")            
            
            time.sleep(60) # wait things to wrap up for just in case



if __name__ == "__main__":
    main()

