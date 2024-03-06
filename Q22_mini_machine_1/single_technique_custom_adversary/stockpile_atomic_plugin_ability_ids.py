from pathlib import Path
import os
##########################################################################################################################
# JY: Updated @ 2023-10-22 based on updated-ver of Caldera


STOCKPILE_ABILITIES_DIRPATH = "/home/etw0/Desktop/caldera/plugins/stockpile/data/abilities"
ATOMIC_ABILITIES_DIRPATH = "/home/etw0/Desktop/caldera/plugins/atomic/data/abilities"

# Stockpile Abilities (#158 ; Note that not all supports Windows-Powershell) -- updated caldera-ver
stockpile_collection__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "collection") #------------------ #16
stockpile_command_and_control__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "command-and-control") #------------------ #3
stockpile_credential_access__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "credential-access") #------------------ #10
stockpile_defense_evasion__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "defense-evasion") #------------------ #15
stockpile_discovery__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "discovery") #------------------ #67
stockpile_execution__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "execution") #------------------ #9
stockpile_exfiltration__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "exfiltration") #------------------ #13
stockpile_impact__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "impact") #------------------ #8
stockpile_lateral_movement__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "lateral-movement") #------------------ #10
stockpile_persistence__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "persistence") #------------------ #1
stockpile_privilege_escalation__dpath = os.path.join(STOCKPILE_ABILITIES_DIRPATH, "privilege-escalation") #------------------ #6

# Atomic Abilities (#1355; Note that not all supports Windows-Powershell)
atomic_collection__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "collection") #------------------ #44	
atomic_command_and_control__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "command-and-control") #------------------ #66
atomic_credential_access__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "credential-access") #------------------ #145
atomic_defense_evasion__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "defense-evasion") #------------------ #410
atomic_discovery__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "discovery") #------------------ #220
atomic_execution__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "execution") #------------------ #91
atomic_exfiltration__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "exfiltration") #------------------ #16
atomic_impact__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "impact") #------------------ #46
atomic_initial_access__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "initial-access") #------------------ #3
atomic_lateral_movement__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "lateral-movement") #------------------ #16
atomic_multiple__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "multiple") #------------------ #249
atomic_persistence__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "persistence") #------------------ #46
atomic_privilege_escalation__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "privilege-escalation") #------------------ #2
atomic_reconnaissance__dpath = os.path.join(ATOMIC_ABILITIES_DIRPATH, "reconnaissance") #------------------ #1

#------------------------------------------------------------------------------------------------------------------------


''' Get all mappings from abilities to their tactics and techniques (for stockpile and atomic abilities). '''

def remove_suffix(input_string, suffix):
    ''' string .removesuffix is supported from python3.9+. '''
    if input_string.endswith(suffix):
        return input_string[:-len(suffix)]
    return input_string



# Privilege Escalation
stockpile_privilege_escalation__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_privilege_escalation__dpath)]
atomic_privilege_escalation__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_privilege_escalation__dpath)]
privilege_escalation__abilitiy_ids = stockpile_privilege_escalation__ability_ids + atomic_privilege_escalation__ability_ids

# Credential Access
stockpile_credential_access__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_credential_access__dpath)]
atomic_credential_access__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_credential_access__dpath)]
credential_access__ability_ids = stockpile_credential_access__ability_ids + atomic_credential_access__ability_ids

# Discovery 
stockpile_discovery__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_discovery__dpath)]
atomic_discovery__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_discovery__dpath)]
discovery__ability_ids = stockpile_discovery__ability_ids + atomic_discovery__ability_ids

# Collection
stockpile_collection__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_collection__dpath)]
atomic_collection__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_collection__dpath)]
collection__ability_ids = stockpile_collection__ability_ids + atomic_collection__ability_ids

# Exfiltration
stockpile_exfiltration__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_exfiltration__dpath)]
atomic_exfiltration__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_exfiltration__dpath)]
exfiltration__ability_ids = stockpile_exfiltration__ability_ids + atomic_exfiltration__ability_ids

# Lateral Movement
stockpile_lateral_movement__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_lateral_movement__dpath)]
atomic_lateral_movement__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_lateral_movement__dpath)]
lateral_movement__ability_ids = stockpile_lateral_movement__ability_ids + atomic_lateral_movement__ability_ids

# Command and Control
stockpile_command_and_control__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_command_and_control__dpath)]
atomic_command_and_control__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_command_and_control__dpath)]
command_and_control__ability_ids = stockpile_command_and_control__ability_ids + atomic_command_and_control__ability_ids

# Defense Evasion
stockpile_defense_evasion__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_defense_evasion__dpath)]
atomic_defense_evasion__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_defense_evasion__dpath)]
defense_evasion__ability_ids = stockpile_defense_evasion__ability_ids + atomic_defense_evasion__ability_ids

# Execution
stockpile_execution__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_execution__dpath)]
atomic_execution__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_execution__dpath)]
execution__ability_ids = stockpile_execution__ability_ids + atomic_execution__ability_ids

# Impact
stockpile_impact__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_impact__dpath)]
atomic_impact__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_impact__dpath)]
impact__ability_ids = stockpile_impact__ability_ids + atomic_impact__ability_ids

# Persistence
stockpile_persistence__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(stockpile_persistence__dpath)]
atomic_persistence__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_persistence__dpath)]
persistence__ability_ids = stockpile_persistence__ability_ids + atomic_persistence__ability_ids

# Initial Access
atomic_initial_access__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_initial_access__dpath)]

# Multiple
atomic_multiple__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_multiple__dpath)]

# Reconnaissance
atomic_reconnaissance__ability_ids = [remove_suffix(x, ".yml") for x in os.listdir(atomic_reconnaissance__dpath)]