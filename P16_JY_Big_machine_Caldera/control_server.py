import subprocess
import os

# os.chdir('/home/jgwak1/tools__Copied_from_home_zhsu1_tools/caldera/')    # Modified by JY @ 2023-02-27
# cmd = ['python3','/home/jgwak1/tools__Copied_from_home_zhsu1_tools/caldera/server.py','--insecure']    # Modified by JY @ 2023-02-27
# p = subprocess.Popen(cmd)

def start_process():
    #os.chdir('/home/zshu1/tools/caldera/')
    os.chdir('/home/etw0/Desktop/caldera/')  
    #cmd = ['python3','/home/zshu1/tools/caldera/server.py','--insecure']
    cmd = ['python3','/home/etw0/Desktop/caldera/server.py','--insecure']   
    p = subprocess.Popen(cmd)
    return p

def shutdown_process(p):
    #p.terminate()

    # 19.3 Stopping CALDERA
    #   CALDERA has a backup, cleanup, and save procedure that runs when the key combination CTRL+C is pressed.
    #   This is the recommended method to ensure proper shutdown of the server.
    #    If the Python process executing CALDERA is halted abrutptly (for example SIGKILL) 
    #    it can cause information from plugins to get lost or configuration settings to not reflect on a server restart.
    #
    # Following works!
    p.send_signal(subprocess.signal.SIGINT) # SIGINT is Keyboard interruption

def main():
    p = start_process()
    input()
    shutdown_process(p)



