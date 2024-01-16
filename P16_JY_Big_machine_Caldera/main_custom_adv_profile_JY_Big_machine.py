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
        
    
def interact_with_VM_for_logging( p, record_time, adversary_id, post_activity_wait_seconds, store_name= None):
    
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

    message_to_send = f"{adversary_id}__postwaitsecs_{post_activity_wait_seconds}"
    # s.send(message_to_send.to_bytes(2,'big'))   # send 함수는 데이터를 해당 소켓으로 보내는 함수이고
    s.send(message_to_send.encode('utf-8'))    
    s.close()  # Close the connection from client side
    
    #-----------------------------------------------------------------------------------------------------------------------    
    # 2. Wait and receive message of "started__logstash__silkservice__caldera_agent" from VM
    s = socket.socket()     # Now we can create socket object
    PORT = 1100             # Lets choose one port and start listening on that port
    print(f"\n HOST-socket is listing on port : {PORT}\n", flush = True)
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
    time.sleep(record_time)
    print(f'end attack for {adversary_id}, as {record_time}s elapsed.', flush = True)
    #-----------------------------------------------------------------------------------------------------------------------        
    # 6. Send message ("terminate__logstash__silkservice") to VM

    s = socket.socket() # Now we can create socket object 
    SEND_PORT = 9900     # Lets choose one port and connect to that port
    s.connect((VM_IP, SEND_PORT))   # Lets connect to that port where socket at VM side may be waiting
    

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






def procedure( pid, rtime, adversary_id, post_activity_wait_seconds ): 

    ''' 
    [Added by JY @ 2023-02-27 for JY's better understanding]

    "receive_sample()" is to start collecting ETW logs. 
    ‘pid’ ("Caldera Server Process PID") is used to shut down caldera after finishing the attack.  
    ‘record_time’ control how long we want to record.


    https://docs.google.com/document/d/1Z7dx2a--M2dUrdub-J-ljwCMSjShgLe1rG4ALChi4ic/edit 
    '''

    #-----------------------------------------------------------------------------------------------------------------------
    # 1. Set up store dir (store sample in tmp)
    #store_dir = '/home/zshu1/tools/etw/tmp'
    store_dir = "/home/etw/Desktop/caldera/etw/tmp"  # Modified by JY @ 2023-02-27
    record_time =  rtime
    
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
    vm_name = "win10"
    #snapshot_name = "snapshot_caldera_custom_adv_profile_20231220_updated_15"
    snapshot_name = "snapshot_caldera_custom_adv_profile_20240115"
    #revert_give_time = 300 # this may not be necessary, but makes it less error-prone.
    start_revert = datetime.datetime.now()
    print (f'\nreverting to snapshot {snapshot_name} -- started at {str(start_revert)}', flush=True)
    os.system(f'virsh -c qemu:///system snapshot-revert {vm_name} {snapshot_name}') # works (confirmed at 2023-03-01)
    #time.sleep(revert_give_time) # -- this results in absolute waste of time
    end_revert = datetime.datetime.now()
    print (f'\nreverted to snapshot {snapshot_name} -- ended at {str(end_revert)} -- took {str(end_revert-start_revert)}', flush=True)    
    print ('one sample sleep 40 sec to reset', flush=True)
    time.sleep(40)


    # JY 질문: 아래 부분은 어딨냐?
    # 4. Wait 40 sec for caldera agent to get the connection with caldera server.


    print(f'start to record', flush= True)
    #-----------------------------------------------------------------------------------------------------------------------
    # 5. Start to record
    # create a server to receive samples 
    interact_with_VM_for_logging(pid, record_time, adversary_id , post_activity_wait_seconds = post_activity_wait_seconds )
    print ('finish')






def main():


    # TODO:
    # 1. Debugger 로 Run해봐 (Connection-refused 고쳐 )
    #   > https://stackoverflow.com/questions/41027340/curl-connection-refused
    #   > netstat -tulpn
    #   > netstat -ln
    #   > You have to start the server first, before using curl. On 8/10 occasions that error message arises from not starting the server initially.
    # 2. Caldera website에서 adversary들 다운로드해봐.


    loop = False
    # t = int(sys.argv[1])
    t = 600

    post_activity_wait_seconds = 300

    if loop == False:

        start = datetime.datetime.now()

        # get commmand 
        pid = run_caldera() # "run_caldera()" starts the Caldera server, and waits to start, and returns caldera-server process-info "pid"

        # adversary-profile should be stored in "/home/priti/Desktop/caldera/data/adversaries"
        # adversary_id = "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-23-20_09_50"
        # adversary_id = "custom_adversary_profile__APT_3__APT3_Phase2_Pattern_1__both__2023-10-23-20_09_43"

        # adversary_id = "custom_adversary_profile__None__None__stockpile__2023-10-23-20_10_55"

        # adversary_id = "atomic__t1003__credential-access__os_credential_dumping__2cc37a6cf2f1acdeaa6a6638016444d1__trial_1"

        adversary_id = "joonyoung_single_technique_profile_for_network_event_invoking_custom_technique"
        #adversary_id = "joonyoung_single_technique_profile_for_network_event_invoking_custom_technique"
        #adversary_id = "joonyoung_single_technique_profile_for_registry_event_invoking_custom_technique"

        procedure( pid, t, adversary_id, post_activity_wait_seconds )   
                                # "receive_sample()" is to start collecting ETW logs. 
                                # ‘pid’ ("Caldera Server Process PID") is used to shut down caldera after finishing the attack.  
                                # ‘record_time’ control how long we want to record.


        
        end = datetime.datetime.now()

        print(f"Elapsed-Time for {adversary_id}: {str(end-start)}")

    else:
        # #doing it in a loop

        adversary_yml_fnames = [x for x in os.listdir("/home/etw0/Desktop/caldera/data/adversaries")\
                                if x.endswith(".yml")]
        
        #already_generated_json_fnames = [x for x in os.listdir("/home/priti/Desktop/caldera/etw/tmp")\
        #                                   if x.endswith(".json")]    

        already_generated_json_fnames=[]    

        # added by JY @ 2023-11-26
        filename_patterns_to_skip = ["joonyoung_no_command", 
                                     "trial_1", "trial_2", "trial_3", "trial_4", "trial_5", # for only "trial_3" (trial-1, trial_2 are already done) 
                                    "db1bb4f8462260edf0e7c4b892dd66ca",
                                    "88d78618bbba0ca862d8d5a6f6fb4d72",
                                    "f6c693da77b8824b3c52ba3b6ca0bf88",
                                    "2cc37a6cf2f1acdeaa6a6638016444d1",
                                    "60bb6f8468aa98b75be2521861a164d5",
                                    "1ae855684c48448c29ad04858bbe5a2a",
                                    "54f95564a265f67159d1f8ff907cd156",
                                    "691d489fe77afbfe8646419fce6759fd",
                                    "82dcefb5c3512d73bf2248cb0127c4ae",
                                    "bbc786e45aff314d33e60133f010f00c",
                                    "24a6ff3816824ecae285f847995709cf",
                                    "3bcfa369fd1f214e4d05944228eeb212",
                                    "6dc5c587fd22d65b81a443b7ce065ab1",
                                    "36fc42ced381416ca7d5d7af0ee0561b",
                                    "3db695e5387d0fd3bb4e53c330814b7f",
                                    "8de14c0ea1b80dbd5de0cf5d28cff16b",
                                    "8e01631039faf6a9a84df376bf9ad0f1",
                                     ]
        
        unsuccessful_atomic_techniques_adversary_ids__20231204 = [
                                    "7b6d0accaab6330d701dea8f4d7d96d4",
                                    "e4c51df716410dc7baccead922f9d9a4",
                                    "57548b3eefc3c3d3eaf8c3b51380921a",
                                    "5e0427f03faf554046c6a29864087b49",
                                    "a9faa0d792d6bc2660b05e7650d2736d",
                                    "79cb459770a15ea9e56b874d62bf8319",
                                    "d5bb3cda05ddba230c90c1afb2640379",
                                    "c0bc49e3838d26569b243ae283082926",
                                    "d6df415c9fbfc30ac359542d67537953",
                                    "b2725f4e411b9328aa73fe54501a7564",
                                    "f7257d271a176f7c609b4a33513d2eef",
                                    "fe3527480a77ab0b52a518654e120b72",
                                    "0d2e984bedf73f5266e250d7ecd257cf",
                                    "548a620bf3463f72a42937faf7614935",
                                    "ed65658e4431bc3b636dd0de29bf8e35",
                                    "d3e69d970c19fb2a9a2ee8be47ea17ad",
                                    "9332aff267b00ede37b09606340ee1dc",
                                    "d74777514cba5a4fd4f297261ed0d8ef",
                                    "48dc8d6cce12ca22b19fdbc93bd3a9ed",
                                    "8ce073cf3170576e1f5c6e4d06e1873a",
                                    "6fb0cdea444d58a340896d606baf281a",
                                    "5e3512c73a461c17ddcb1cc0bbdbeef9",
                                    "6e3d4c708ab0ff571eb05691cc8bcdda",
                                    "e0c75b4cc32124ef4c61508694fd0808",
                                    "f782c9b7007a34343faec301b64e7435",
                                    "214be4092770061080ef0781c26bab3e",
                                    "a3c8fba61f02a7b96306b87121b2ac4b",
                                    "04858322bc6cd08282f2ce96cab5ee7c",
                                    "4f277a5607b655a2e5bc05ff21ed81cf",
                                    "c7aa16aea441e7bec9a6391af601acc9",
                                    "bf9cc3d98c38f79c948a0f4a7f888034",
                                    "6f5096d87a8f9ac4c397215cb58cc978",
                                    "07b384a102f27412c1475421f4534f29",
                                    "2594698a8e38a85b0d98468d87b49821",
                                    "d143172642328567d9d0951cb116e3a2",
                                    "820a346b2b676b51338c1170b675f76b",
                                    "d54bcaf2e58f6d95da2a54dcb5853a57",
                                    "358926f4adef63bf95d152e35df4dab3",
                                    "08faa1ff79f2c8e48a2869a830c210f7",
                                    "a45769d74eb1c75ff916b121023bde31",
                                    "628181210e822588b5d90e1e256d775a",
                                    "9ed218029d8392d2b4fdedd0f44bb052",
                                    "5a1dc4ce41e376e1928d3a399ccadff3",
                                    "305c23215a4bf6184ed701b5ca1d1af7",
                                    "3f588ff884129699e1b9a56f2248bc3b",
                                    "5fef676a9954938537bd1e2191d3e9b5",
                                    "6913e132cdd2d9c29294490c2fbef2eb",
                                    "587a8743222626915bb08b3e9e132b19",
                                    "ce67d9c1b111032ddb8a56363c854fdc",
                                    "7a4867f379d79c82f217108c48bdbf33",
                                    "4572792b7173c41d22a827610b8f8890",
                                    "c5951c819c5f6125e0e5987a12a344f9",
                                    "08a146a382df6fea9fa2275073e9d245",
                                    "cb6e6c7e18aba2207c696368f8edb23a",
                                    "47ba984c0c40a7c41b4797156c1a5f96",
                                    "9c2f9c808a72b05686236a63e1da93c8",
                                    "4bf4facd1dad540d4b17ebe0db235707",
                                    "b45cb08e24877077d98421393bce079a",
                                    "03c8721619373b6c18a55721a33cad2c",
                                    "f7c881e0d021a2f5b45546b5d0b4998e",
                                    "48a861eb5802bd7abdaa64b4fcd30924",
                                    "938a659c52ed102a8b35c7b1bb49eb11",
                                    "085858a8aa5ea8e6a810e59c75ea7f6a",
                                    "e541c2b62c3259680863a6f3b410e59a",
                                    "dce08779676c01d98885e164a1176ac8",
                                    "566b2f5743d88edb44ad1d9d450e921c",
                                    "70f8b4c0be2ee69f07592eee0aa5acc0",
                                    "ce2eccff2f1de0096efa0da778a7e27c",
                                    "c75a55384a1e7026bb91f841e4ca2ba9",
                                    "c905c33c06f38484cab101ae93a93a9a",
                                    "126aaf80c6a232eaf08dcef3163d4aed",
                                    "409acf7907007b041753a5f452b3df9b",
                                    "4e9bac619326378b219b3635c9a91b94",
                                    "8cd2639cb742872b58a2356909628376",
                                    "7197a8fcd7e833f42251ee3eddaa87c1",
                                    "7844eb9751d121b16f9517817a31eee4",
                                    "e528524d6a3cddaaddc89fcc719e2a3f",
                                    "0954576f69ca8e140f2cdc9e58b36ff9",
                                    "d7967a23c8c030c698893f242e622be1",
                                    "0690e0818b5749092595a472831f362f",
                                    "72784d12700b219ec134aa42cec5603e",
                                    "5b1aea789aa50c07bb5555dcff5d42a6",
                                    "1ddf2b8ee6a56ce9f9132a168947653e",
                                    "bdc2a80d621d3361ea727008644b1d15",
                                    "ba8ddc38c7c6ced12fecc0d695c5e57c",
                                    "1532b3faf25ad1e6f4fba4ada643b253",
                                    "b62952c5352ee68c1340feb08a5a02a1",
                                    "ef943918da20ee40d378ad000bbcc3b7",
                                    "aa758d17faffeeb69c56481340891859",
                                    "834e861bba95b87d066e84c5c6b056a0",
                                    "9b3194cc656092b09f4d79ba3d3a3277",
                                    "6d0695f8f33776c82ad1294b6c6f02cd",
                                    "9d21f3b551b40fa40056af1244af56ee",
                                    "d8dbc446fea6514a712803194b10cb75",
                                    "7f0f5471543a6f188b0fbdc436c49fd9",
                                    "4150ef18184112953ae5742a3f8de64e",
                                    "aabe23a58568de3f9cc40e42e5f1b223",
                                    "ff4e1ea516f781a6ef93323ba9dfac0a",
                                    "57781057e51ffecf21e38fd31c9d2f79",
                                    "a18a0e98b9566d92a1611a2da69b413b",
                                    "0f3401d54f59bc1c3eca134ad5d8a774",
                                    "f71199dcf1e307fc37c5a0cb9e4031b9",
                                    "6d968b2bfa7f45550662620724618fb9",
                                    "cea891e7c3c3efe3723eca495d261472",
                                    "6722535bf5a14b87b5772b739f53321f",
                                    "0fccd1bb314f0b3cbffd27c2123ae955",
                                    "9ac97b0e88af420a8c767a7512985895",
                                    "52928f462ea8f5fa617aa8c815f5598b",
                                    "9eb61c26282c5b324e1fb6cceeefc445",
                                    "1033c974479429c54dff4470e614113d",
                                    "5ce7136a4547b0bf3ca074c94fb10b24",
                                    "21363f92027047ce1dbfdd47f7a483b5",
                                    "64ccf7cd4358a0540ab51c8015c1b744",
                                    "8ed60dceb98746f1da6214f4f6af7164",
                                    "13a0c78dbd8d3645db69540bfe7cd038",
                                    "1c1381522818218092a12b973593f3a9",
                                    "80cda763aa992b775038ce134c892070",
                                    "45aa13ed61bbe98aaf9324ce8044c860",
                                    "29d32b9096933705ce0fffc441283b20",
                                    "b8e136dad1af7b29939e86be6d7ecefa",
                                    "8b5f748da9647a4d9c5a37f20124ba9c",
                                    "582871bcbf9a88caed89ae25d76d018c",
                                    "b66a6eed7d46ab2ca4c3bf1ae3b61f44",
                                    "6b8a391237b7169d02dd6538f8290345",
                                    "e8c24e75714483eb3b526fc589a88f9a",
                                    "84a93e5157b690ee0f585cd55c15b0cb",
                                    "ff659febed01ef020792aa5f83d08d6d",
                                    "566388d2f3073aced1a2c86b3a65826c",
                                    "d2e0c0165046372fcd5e2bf910eeb477",
                                    "1f2da2639fcd636ef1c7ead72de4469f",
                                    "163fd8a878476002c604d0fe4e32a419",
                                    "16e96b0f0c0021663b2f5dfafabee6f0",
                                    "725f6e03f3e2098c4303861566f18894",
                                    "1cca72410c2849070d833700fcc30c59",
                                    "954860df5054a5fabc114abefd8e45f6",
                                    "25b475e94dd2d70fcc66b2ce43c8f718",
                                    "ae73a53476995f46b71f11709f525319",
                                    "53187e13ccee0b0d71451ca3fdc1f9d9",
                                    "20d68348c822d2947e5a795ac15a22b0",
                                    "e538e0ff74962aaf1dbd08baa5c7853f",
                                    "114ad8aad10ca59e6a10b655764d749a",
                                    "78931aaa8e328d30a3e47f61e2899b3b",
                                    "d0966749d457cb6218a8cd5ee5128ea2",
                                    "fdc26580786ac9d3ffc38aea053cbd29",
                                    "a9df2530a06e1aa7d1ba9e9309364b9f",
                                    "90c76bd616efee6d7c98dc6c1dcc6e99",
                                    "89a4fca013d3d39fc4effb1f6c8a8d74",
                                    "f39aace719f4cdcf8569001f7a25aabf",
                                    "fef50b36806647cb5a5511ae48f7e56f",
                                    "0ecc3d4729cf37c719528291d63f9f99",
                                    "0bb6fa90a458e6512a19d246cfae8843",
                                    "f50ec080343f1bec4e739dd20675c349",
                                    "7cd26e24cc23c5a7e1183120fa034f89",
                                    "396dae93ab07f7c93853def404fefebf",
                                    "1d48fc4147a7bcd47bdf60db7dde9640",
                                    "95f9e48ea1fbdac2f1c7c656b655ae4c",
                                    "f32d25602b6c142d321b9a0965316916",
                                    "7f43a2b144f2534eb979d2b6638e0283",
                                    "196263c4c1f42138866d958193ad2ad4",
                                    "51ef5578afcd873709d2c7672234e57b",
                                    "51ddafefb92c9dfcb6ce3369e7316bf3",
                                    "36a790779a43eb407e4852726be0c66e",
                                    "495536c73651969fd80a8f263c293194",
                                    "f5b48f9f8e01db3edd487c05580a0e90",
                                    "3ed2af2ffd2e21a9b97fbfb732ef3971",
                                    "2ca71106ee0aff2eda551bb6ed2b39e4",
                                    "f22a27383f804337af8e690aae594d97",
                                    "009e7a7118b5a182b2a5b65150e5cc6f",
                                    "824ec334619ca634d13aff308a9a064c",
                                    "f5b4c02bae169cb3a62ac26bb80321d6",
                                    "6fa417fb183d6c20a67e617c0249f04f",
                                    "3d628a543cd195d2a19b89b76a8e5d74",
                                    "248be98ef985ef5053a26ed7cd929c14",
                                    "029770bd7c3a403daeab3af692af0046",
                                    "ae1510936a20ac31014eb86e5b4944ce",
                                    "01a2ad691dfb47b11d050fab371718d2",
                                    "b939c81cba750f4b3ef67e6b0456b41e",
                                    "45f462c09f28d5b0819af7b1ed0913e1",
                                    "1353d954c020fa5ff039b7e85ee261bc",
                                    "23daed0787180c7f2ffbc20528570749",
                                    "d21a964d09837abede8966daf6ae46cf",
                                    "4df316c222125fe7372723c5b3434977",
                                    "2ed8948f1c1156af47d50379e7965d90",
                                    "9d0478981edda6091f911a1305025bde",
                                    "a59dbd1a2ac17d69455248e7d91231bc",
                                    "a967003ff25bdd94030cdd885feb25d7",
                                    "c29f0da7c0bf612d30acb64e1d6e9368",
                                    "0a96ef5851da1be487cebdd9a1f86b7a",
                                    "b74b60096fb49650e27e470047a2b9c9",
                                    "6d3a92f7fc3d8abeea37531cfba7c79e",
                                    "6baab84fe7a52dd5c4ede612fc0d255f",
                                    "10a0f4f8efdae71f3e88b3e20560798a",
                                    "fd4ca8f12c6d3a9af55be0211878509b",
                                    "a935a79ba61ecb00458208b0bd5ef15e",
                                    "f5cef6032e9bace6a1938456ac5a5cfb",
                                    "f071213a29669283eeb8ab07ddffdbfb",
                                    "1ce0e92b4cd09129c6d0f3aafb38c600",
                                    "6940ffd670787cd1c410997e66629573",
                                    "2cda9de49fe7ac16813a23d0741e9b28",
                                    "4c378a952a9235b7aba7f273f3cf4874",
                                    "7030b003cc5646c7cc83410d2f057575",
                                    "38714562d32f33dc32bd7aef553771d9",
                                    "279d24eeb12b40e4547945accf59ca62",
                                    "5458332f329c896a133982a7df20d358",
                                    "54b98f924ee4613c7d927a3ea1dd260a",
                                    "d7f1270ba66d5947a1422f7d5b1a36ef",
                                    "e0e717c540d5e8ff24f00b7434626f7e",
                                    "d9c1b1283c1ad6fdda27be021c4737d3",
                                    "3b4fb2e38c41453a6b2b0f2fecdd84ff",
                                    "68ce066d07960123ccd981dd8c38a7c1",
                                    "623806a6fd4d832b6692eb275535f636",
                                    "35200ef3d7ca094ae2208a1df03ede18",
                                    "aeb4fdbb3453127caaef0ad5c250d838",
                                    "bc34d6834bdf568e206627f7809a556f",
                                    "c6ea575d9641c11410417105f14175ab",
                                    "73fed1f32224461748c3630217b7d300",
                                    "86993ae14d75a6da421c0d98c3facd61",
                                    "885997e230cb2b9dc3cc7e9d8ec5a6d8",
                                    "ed172018f897dab90147a47995ce197d",
                                    "5fd6b6b635191898a202dc7c21aa6068",
                                    "015d186adee85e65d7255b383e1a039f",
                                    "f91d7dfb1e6fd4fa742f24927ca4af26",
                                    "ffe23675b3b68eb6d2b6e771451de3af",
                                    "d2f6cb279552f1b65a9805d63eed1689",
                                    "69b202bf0bb7b4ff43d4abb8867c1784",
                                    "b5fe84fa9fb8216512867a039a61db20",
                                    "53571e9988b92014f9d71888936d3878",
                                    "fff25debffb3645d82c89632750497a1",
                                    "aaeee9107989a507f526b0cef1cb274f",
                                    "560688901ad2b8f465e98c52379ae834",
                                    "50df8303a555242bea67342db40d0d47",
                                    "986876c6024765475043100f9e080fc8",
                                    "1827aa5862b0a63ce537ed37636933d5",
                                    "54ef63765cf80243f370958bcf738338",
                                    "608b7021a5b8369e9fd858feba6f5611",
                                    "65e9fb2b4c023de2a2a73de5cc58ce7f",
                                    "4b325a29e936cd1ccac2292bc92a31b5",
                                    "7a87eec9166dd9d24825a4af7bb3bc47",
                                    "8c0f619c7dfd33907bf20b1dfb58022b",
                                    "8beb34c915b17873e357c030d517be0a",
                                    "995eb25ee0b9d036110318311ca2527b",
                                    "f5606cc7632289d5ca72d4a485c14f6b",
                                    "e6a9fe7e91030f05ad87b75ad4fd4a3a",
                                    "e922717a38fc8806bc9b56b111b999ff",
                                    "91a18ae1efe4119a549cea2ac7de72c4",
                                    "f2d48f9efed23e058bfe0f46d93d07a2",
                                    "5d4905a2f789ff40c53b1ea8ee53df3d",
                                    "03a80d4a4c02d99295b5901ee695cc79",
                                    "83a5ad479c9e313e60f34380e193102a",
                                    "8aabc61664e947c69058c3df4f3af860",
                                    "3aae7c6d210ffb084186f1686a1f00c1",
                                    "2f03250355bb1403dcfac6808782a192",
                                    "aee64e494f7adfb1867d67f7ee08e5c6",
                                    "4712f45e41760276d20885bbc885a2ef",
                                    "c1392878b0e39a2060e7e1b70e5a580b",
                                    "413fc5fa7ac34f8a42183217d7f3ec90",
                                    "286916316d725933021d57fb5620d644",
                                    "afae914d4839d5194835d8475604e7b8",
                                    "941eb886a05444e588fd6c17d992df98",
                                    "e9e69b4fedb8e40d634865ce9a3192dc",
                                    "e5279c9ad109fef655e2c1abd6304725",
                                    "106045f14741390cfb3fe95300585fb6",
                                    "53d41aa7edbb10cea4c99df8c2b0862f",
                                    "77e4fd90d211edf046c6c7092a4ed3af",
                                    "2f4c11504a21b8771b725a3e469fd74b",
                                    "44c554d9bf01759c8a35c8ec8eb8510d",
                                    "6bbb6f8b1db42e2c2c79892e8c31feb3",
                                    "2db3b2385ba856424bfe130f69fc0529",
                                    "3b631d04243ac011df9f91cd07025180",
                                    "981cf81e3bb0649fafc31217c8cbc00d",
                                    "9995c62a6263a14ae3b60fe2bb52e67a",
                                    "31a7326fcc56c71d97da23e3fe1ec364",
                                    "c84a57391dbc724dc51436deb3e0ca00",
                                    "8862278ba483c0d5f719ffbc9186a901",
                                    "b97004a5d9c4283b6085ddf3ff0d6b4c",
                                    "7a6e495200cd37c66f02e7bc070b61a9",
                                    "58351281e64f2182ac4f8b44f63e9042",
                                    "3d7b7a1676afefc4af9506003b2d58d1",
                                    "61e9071d7b1f01969893d015526e1099",
                                    "fca2ce47cdb3acfde35139ca9017af80",
                                    "f6d9c3fbee5549837ea37ff933291656",
                                    "7a0717485ca13c441d26bfaaa5c92535",
                                    "bc5d26cf7201f1504b495ca2c1758ebf",
                                    "000549902a51ef21f57d3d28a6e5ecc0",
                                    "f6867f2b9b1b3c2eb733ad7ce7438f04",
                                    "03a127453d425bf1fd8dc9af1ed7ddce",
                                    "748882eaad1b31e8f90d9b31692200fe",
                                    "2c6e39a39ebf794d74417a7b1291463b",
                                    "6e214f0f17e5d4988aa1085ad4291f46",
                                    "c0177717b47f2cd07949186523fa3c6b",
                                    "f21623deb932dc0db3f00068ba15bf32",
                                    "1272c02ca685d9967ee2be885dea8df5",
                                    "7f734143338de2b02093a703f919e7fc",
                                    "9e1358e1b78af4bf86bab2334485a015",
                                    "efdca41c8a098f89f2db9c334627d8ac",
                                    "e93d024cd93ceaaf880d6f799ef1c9c8",
                                    "bba7fe7940f8719efa3c38e54ec79e2c",
                                    "3f73be176cadf2762623b3117e25335d",
                                    "f1dcadde207fafe338ae3eb48805f23c",
                                    "1bb96a80fd7968839ead470953ffb738",
                                    "7440c68b83b6d728b4111d083facefec",
                                    "55fa0d4a61d03d34c0628b6b5343cac7",
                                    "36aa805044ab4f4d7f6f372a46c8bab2",
                                    "4bdc05fe2f0006f86575053dc740edf3",
                                    "2d78dfbfea7fa4ec7349993b83048079",
                                    "a8a3487e477e0c1501ceb0239b5cad15",
                                    "681fd384d66be9e180a74e5fecdc4ab6",
                                    "f5dd56d901db9f95668988426326bc3a",
                                    "5e744dc6fc70da028ccd50f7e73ee0be",
                                    "e958169f1efe85a5a5ea7a77eba8c29e",
                                    "c087fa2d3870144b9fd442f476e7768a",
                                    "8bdb353bbee5378745783ff6f2d49cb0",
                                    "b7f89af9214876eae185527350ca034f",
                                    "8c4228fa7e1c015590d1f13d935e5bb8",
                                    "aa40e8fe704a97fb7f7a5a02e9334824",
                                    "a72efdca009d9d28e444240e691a4769",
                                    "5ee8fce78c4cef28c4e6ecebe77bdba4",
                                    "c275ffb52331397b42ebc52338be3c8c",
                                    "35b68f98acbdbdde166d4154462d2467",
                                    "e5168b0f7e57ba7b20c9842a350bb539",
                                    "9d03b18c922b94ebba44d25c430e6e95",
                                    "679ef375ad2b361965500392419d084c",
                                    "4de0ba1566249a72e81e74707cc91a00",
                                    "3c9dee6c65974cc3b4f34d0a5d1b6992",
                                    "9381d0e0efbf5bf89a9e512f8b3745f4",
                                    "c285cfeaf0c226d3d2b3812726dbe3a8",
                                    "d1bde9af5206152c9980a5b6adcc1813",
                                    "337c07ce279b747827679ffb226e5d9c",
                                    "56c2f2d8b48bcb1c999d4e8929bd8d9b",
                                    "cfcf66cc85109ad2ebdb301d619fa41f",
                                    "01f95fd0213aeb1eb07fca8dc548f5ce",
                                    "2cdcf1010a524231a26b5f3c6025eb91",
                                    "f27b37f253617c39ac010d2ee1238b7e",
                                    "b26ce33f4cd29428f619fc600e052350",
                                    "50a9be8bbff4d4ffe0b699cb8d040c6d",
                                    "ac7757ba58f423fa808b4b6f115cc613",
                                    "3c8ae3452b200f3509b14463df78068c",
                                    "107a14acdd84a7d6e7c891177b0db3aa",
                                    "04d33ddae0126966ae6d841267c17329",
                                    "4df4fdb269f34dd6d55969c83ff06c73",
                                    "7532005da662bfc703ce3d8ef4e8ac70",
                                    "0402c74f97e712d03605175c5ba9675b",
                                    "4abdd4cce7c4aa8a3804a6f5ff365514",
                                    "2d2b2b31b70f1beef285b942c580f4c3",
                                    "cc5347b500dfbdbb96b1fdb6a0669708",
                                    "5a33c31395b6ef3ee38097b327c8b79d",
                                    "beafe61e6874eb9eec2119bd12255193",
                                    "ef2c951840423ba90c208867dcf89c87",
                                    "627f499ceb32e74b95494141bc680e08",
                                    "abeb340acb3e1236c6919339942e7c77",
                                    "bda00f459bb9118c4c88de426055e180",
                                    "9ef143154774a6d0d74e0828e90290ac",
                                    "e643e21318c069d0a576da91650c76fe",
                                    "42102f01777d40a7db982282c4c791e9",
                                    "b00d08275bb2b3ef620e103b1fd7b9e4",
                                    "e2e6f33cf77d10e3c82c244014da20c5",
                                    "a515bb54fd6e14b78297814875f3c73b",
                                    "488ec76af9bd3c5d9feb1d660504b541",
                                    "c58ba91431b9d73d726ccdd7d030a694",
                                    "ba763ea19604a73e3e1f9d9d8d86d9cc",
                                    "5b0527d3382ac91860501cccc9595348",
                                    "608e19b5f7e210ba73e207289e5a1314",
                                    "abc280f400f218aa1f4d5efe3c9e8228",
                                    "eedc7881da4d2fddb5c56fb96aaeecfd",
                                    "b7e7e9eb804006a78cdd75940f7b7c3e",

        ]

        filename_patterns_to_skip += unsuccessful_atomic_techniques_adversary_ids__20231204


        def remove_suffix(input_string, suffix):
            ''' string .removesuffix is supported from python3.9+. '''
            if input_string.endswith(suffix):
                return input_string[:-len(suffix)]
            return input_string


        adversary_ids = [remove_suffix(x, ".yml") for x in adversary_yml_fnames]
        already_generated_adversary_ids = [remove_suffix(x, ".json") for x in already_generated_json_fnames]

        # error_invoking_adversary_ids = [
        #     "custom_adversary_profile__None__None__stockpile__2023-10-25-21_10_24"
        # ]

        adversary_ids_to_generate = [ id for id in adversary_ids if id not in already_generated_adversary_ids] \
                                    #  + error_invoking_adversary_ids ]

        # JY @ 2023-11-07: Sort it so that same technique's trial 1,2,3,4,5 are done.
        adversary_ids_to_generate = sorted(adversary_ids_to_generate)
        n=0

        for adversary_id in adversary_ids_to_generate:

            # added by JY @ 2023-11-26
            skip = False
            skipped_pattern = None
            for skip_pattern in filename_patterns_to_skip:
                if skip_pattern in adversary_id:
                    skip = True
                    skipped_pattern = skip_pattern
                    break
            if skip == True:
                print(f"skipping '{adversary_id}' b/c it contains '{skipped_pattern}'", flush= True)
                continue


            time.sleep(5) # wait things to wrap up for just in case
            print(f"\nStart for {n}/{len(adversary_ids)} : {adversary_id}\n", flush=True)
            start = datetime.datetime.now()
            print(f"{adversary_id}",flush = True)
            
            pid = run_caldera() 
            procedure( pid, t, adversary_id , post_activity_wait_seconds) 
            
            end = datetime.datetime.now()
            n+=1
            print(f"Elapsed-Time for {adversary_id}: {str(end-start)} -- {n}/{len(adversary_ids)} indices are done", 
                  flush= True)
            time.sleep(60) # wait things to wrap up for just in case




if __name__ == "__main__":
    main()

