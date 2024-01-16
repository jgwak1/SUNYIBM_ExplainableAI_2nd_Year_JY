

#b176f4b1-a582-4774-b6f6-46a2e11480af
import os
import subprocess
import ast

import json

caldera_ability_id__MitreTechniqueID__map_dict__ablistJY = json.load(open("/home/etw0/Desktop/caldera/etw/caldera/caldera_ability_id__MitreTechniqueID__map_dict__ablistJY.json", "r"))

# Modified by JY @ 2023-03-01, so that this function takes input-argument of adversary_id. 
#                              By default, the adversary_id will be the the one for our random 5 action custom adversary-profile.
def create_operation( adversary_id : str = "b176f4b1-a582-4774-b6f6-46a2e11480af", post_activity_wait_seconds = 3600 ):    


    ''' JY @ 2023-10-21: Adversary yml file should be placed in /home/priti/Desktop/caldera/data/adversaries'''
    
    #print('do not change adversary id')

    print(f"Input 'adversary id': {adversary_id}")

    #cmd = 'curl -X PUT -H "KEY:ADMIN123" http://localhost:8888/api/rest -d '+"'{"+'"index":"operations", "name":"testop1","adversary_id":"b176f4b1-a582-4774-b6f6-46a2e11480af" '+"}'"
    
    cmd = 'curl -X PUT -H "KEY:ADMIN123" http://localhost:8888/api/rest -d '+"'{"+f'"index":"operations", "name":"caldera_custom_adv_prof_operation","adversary_id":"{adversary_id}" '+"}'"
    print (cmd)
    # curl -X PUT -H "KEY:ADMIN123" http://localhost:8888/api/rest -d '{"index":"operations", "name":"caldera_custom_adv_prof_operation","adversary_id":"b176f4b1-a582-4774-b6f6-46a2e11480af" }'
    #os.system(cmd) # JY @ 2023-10-23: What if we capture cmd of this?   
    # https://unix.stackexchange.com/questions/418616/python-how-to-print-value-that-comes-from-os-system
    stdout_bytestring = subprocess.check_output(cmd, shell=True)   # JY @ 2023-10-23 : could get PID and needed info here? Yes, can do it.

    # https://stackoverflow.com/questions/14611352/malformed-string-valueerror-ast-literal-eval-with-string-representation-of-tup    
    # 
    
    stdout = stdout_bytestring.decode('utf-8').replace('false', 'False').replace('true', 'True').replace('null', 'None')
    stdout_dict = ast.literal_eval( stdout )[0]

    operation_uuid = stdout_dict['id']
    operation_name = stdout_dict['name']

    caldera_agent_process_exe_name = stdout_dict['host_group'][0]["exe_name"]
    caldera_agent_process_pid = stdout_dict['host_group'][0]['pid'] # can get it here!
    caldera_agent_process_ppid = stdout_dict['host_group'][0]['ppid'] # can get it here!
    caldera_agent_paw = stdout_dict['host_group'][0]['paw']
    operation__adversary_id  = stdout_dict['adversary']['adversary_id']
    operation__adversary__atomic_ordering = stdout_dict['adversary']['atomic_ordering']
    operation__adversary_description  = stdout_dict['adversary']['description']

    # [caldera_ability_id__MitreTechniqueID__map_dict__ablistJY[ability_id]['plugin'] for ability_id in operation__adversary__atomic_ordering]


    created_operation_info_dict = {
        "operation_uuid": operation_uuid,
        "operation_name": operation_name,
        "caldera_agent_process_exe_name": caldera_agent_process_exe_name,
        "caldera_agent_process_pid": caldera_agent_process_pid,
        "caldera_agent_process_ppid": caldera_agent_process_ppid,
        "caldera_agent_paw": caldera_agent_paw,
        "operation__adversary_id": operation__adversary_id,
        "operation__adversary__atomic_ordering": operation__adversary__atomic_ordering,
        "operation__adversary_description": operation__adversary_description,
        "post_activity_wait_seconds" : post_activity_wait_seconds,
    }


    print(stdout, flush=True)
    print("",flush=True)
    print(f"operation_uuid: {operation_uuid}",flush= True)
    print(f"operation_name: {operation_name}",flush= True)
    print(f"caldera_agent_process_exe_name: {caldera_agent_process_exe_name}",flush= True)
    print(f"caldera_agent_process_pid: {caldera_agent_process_pid}",flush= True)
    print(f"caldera_agent_process's parent-process pid (ppid): {caldera_agent_process_ppid}",flush= True)
    print(f"caldera_agent_paw: {caldera_agent_paw}",flush= True)
    print(f"operation__adversary_id: {operation__adversary_id}",flush= True)
    print(f"operation__adversary__atomic_ordering: {operation__adversary__atomic_ordering}",flush= True)
    print(f"operation__adversary_description: {operation__adversary_description}",flush= True)
    print(f"post_activity_wait_seconds: {post_activity_wait_seconds}",flush= True)


    out_file = open(f"/home/etw0/Desktop/caldera/etw/tmp/{adversary_id}__postwaitsecs_{post_activity_wait_seconds}.json", "w") 
    json.dump(created_operation_info_dict, out_file, indent = 6) 
    out_file.close()
    
    # fp = open(f'/home/priti/Desktop/caldera/etw/tmp/{adversary_id}.txt','w')
    # print(stdout, flush=True, file= fp)
    # print("",flush=True, file= fp)
    # print(f"operation_uuid: {operation_uuid}",flush= True, file= fp)
    # print(f"operation_name: {operation_name}",flush= True, file= fp)
    # print(f"caldera_agent_process_exe_name: {caldera_agent_process_exe_name}",flush= True, file= fp)
    # print(f"caldera_agent_process_pid: {caldera_agent_process_pid}",flush= True, file= fp)
    # print(f"caldera_agent_process's parent-process pid (ppid): {caldera_agent_process_ppid}",flush= True, file= fp)    
    # print(f"caldera_agent_paw: {caldera_agent_paw}",flush= True, file= fp)
    # print(f"operation__adversary_id: {operation__adversary_id}",flush= True, file= fp)
    # print(f"operation__adversary__atomic_ordering: {operation__adversary__atomic_ordering}",flush= True, file= fp)
    # print(f"operation__adversary_description: {operation__adversary_description}",flush= True, file= fp)

    # print()
    ''' TODO @ 2023-03-05: If we use above "cmd == curl -X PUT -H" does that result in a 'process' in the VM? '''

    return created_operation_info_dict


#create_operation()


