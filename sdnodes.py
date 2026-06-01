#!/usr/bin/env python3
# SDNODES VERSION: 1.12
# 
# Purpose: To display cluster wide information about all nodes within.
# 
# Requirements:
#    The application is generally to be run from inside the directory containing the extracted support bundle, where the file "ucp-nodes.txt" is located.
#    NOTEWORTHY:
#       You now have the ability to specify a support bundle directory rather than being pwd where bundle resides, see options below.
#  
# Fixes:
#  Added >>> MASSIVE <<< error checking !!!!!!!  in order to prevent corrupted support bundles from causing program to terminate
#  
#  
#  
# Changes/ Enhancements:
# ** Expanded output to include additional columns depending on command line inputs.
# ** Added:  Specify a support bundle directory (rather than being pwd where bundle resides)
# ** Added:  Add AccountName and/or TicketNumber and BundleDate to the output
# ** Added:  Send console output directly to an output file (along with fully qualified path if desired)
# ** Added:  Semicolon delimited output for importing into a spreadsheet (see pretty)
# 
# --pretty {0,1}              Set pretty level: 0=Off(default use a semicolon (;) as delimiter to import to spreadsheet), 1=On (no delimiters)
# --outputfile OUTPUTFILE     Output file name (e.g., test.csv)  (default = nodes_output.csv), can have a fully qualified path for placement, else placed into pwd
# --filesave {0,1}            Turn on saving to output file.  Default=0 disabled. If enabled see --outputfile
# --accountname ACCOUNTNAME   Used to supply an Account Name if desired. Default = <undefined account name>. If using spaces in the Account Name be sure to enclose them in double quotes
# --ticketnumber TICKETNUMBER Used if you want to show output associated specifically with a ticket number. Default = 00000000
# --bundlepath BUNDLEPATH     Path to where support bundle resides. Default = .
# --bundlecreatedate BUNDLECREATEDATE  Any string, preferred style: 2025-07-21T06:51:40.000Z
# --extended-output int       Additional output, for now if >= 1 then displays hardware info
# 

import json
import os
import fnmatch
from operator import itemgetter
from functools import reduce
import re
from pathlib import Path
import signal
import sys 
from pathlib import Path
import argparse
import time
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class Options:
    pretty: bool
    filesave: bool
    outputfile: str
    accountname: str
    ticketnumber: str
    bundlepath: str
    bundledate: str
    extended_output: int
    debug: int






def debug_print(level_required: int, current_level: int, msg: str) -> None:
    """Print debug message to stderr if current_level >= level_required."""
    if current_level >= level_required:
        print(msg, file=sys.stderr)

ucp_nodes = 'ucp-nodes.txt'





#---------------------------
# This method simply finds a file and returns directory and file name(s)
#---------------------------
def findfile(topdir, f_glob):
    for d_name, sd_name, f_list in os.walk(topdir):
        for f_name in f_list:
            if fnmatch.fnmatch(f_name, f_glob):
                return os.path.join(d_name, f_name)

#-----------------------------
# This method will search for a specific file, or wildcard file, for a specific host (directory) which contains a specific string
# Very specific for support bundles and not generic enough otherwise
#-----------------------------
def getddcver(nodename,f_glob,k):
    f = findfile(nodename,f_glob)
    if f == None:
        return '-'
    else:
        with open(f, 'r') as r:
            j = json.load(r)
        env = j[0]['Config']['Env']
        imgverstr = [s for s in env if k in s]
        imgver = imgverstr[0].split('=')[1]
        return imgver

# --------------------------------------
# This method prints to console and also an output file if specified.
#---------------------------------------
def row_print2(row, widths, outfile=None, *, pretty: bool = True, sep: str = "  "):
    """Render one row to stdout, and optionally to a file handle.

    This preserves the original behavior:
      - pretty=True uses two spaces between columns.
      - pretty=False uses semicolon delimiter.
      - each column is padded to the computed width list.
    """
    # Ensure we always stringify values (None-safe)
    cells = ["" if v is None else str(v) for v in row]
    # Pad each cell (left-aligned) to its column width
    padded = [f"{cells[i]:<{widths[i]}}" for i in range(min(len(cells), len(widths)))]
    # If for some reason there are more cells than widths, append unpadded
    if len(cells) > len(widths):
        padded.extend(cells[len(widths):])

    line = sep.join(padded) if pretty else ";".join(padded)

    print(line, flush=True)
    if outfile is not None:
        outfile.write(line + "\n")
        outfile.flush()


def parse_node_gpu_flag(path: str, target_nodename: str):
    """
    Scan a kubectl-describe-nodes output file and, for the section whose
    hostname matches `target_nodename`, return (hostname, gpu_flag),
    where gpu_flag is 1 if 'nvidia.com/gpu' is under its Allocated resources.
    """
    if not os.path.isfile(path):
        return
    
    with open(path, 'r') as f:
        lines = f.readlines()

    # Find the indices of all sections (lines starting with "Name:")
    section_starts = [i for i, line in enumerate(lines) if line.startswith("Name:")]
    # Append end-of-file to make slicing easier
    section_starts.append(len(lines))

    
    for idx in range(len(section_starts) - 1):
        start = section_starts[idx]
        end = section_starts[idx + 1]
        section = lines[start:end]

        # 1) Extract hostname (up to first dot) from the "Name:" line
        name_line = section[0]  # guaranteed to start with "Name:"
        full_name = name_line.split("Name:")[1].strip()
        hostname = full_name.split('.', 1)[0]

        # 2) If it’s not our target, skip it
        if hostname != target_nodename:
            continue
        
        # 3) Scan this section for "Allocated resources:"
        gpu_flag = 0
        for i, line in enumerate(section):
            if line.strip().startswith("Allocated resources:"):
                # look at the lines immediately following until blank line
                for sub in section[i+1:]:
                    sub = sub.strip()
                    if not sub:
                        break
                    if "nvidia.com/gpu" in sub:
                        gpu_flag = 1
                        break
                break

        return gpu_flag

# --------------------------------------
# This method calculates and returns full_os_text, hypervisor, node uptime, subnet mask, node_kernel
#---------------------------------------
def full_os_details_v1(hostname, ip_add, bundle_path, debug_level):
    dsi_os = "NoInfo "   ## docker system info result, setting a default value
    
    if bundle_path != '.':
        dir_to_search = bundle_path
        dir_to_search += hostname 
    else:
        dir_to_search = hostname 
    node_dsinfo_filename = os.path.join(dir_to_search, "dsinfo", "dsinfo.txt")

    os_type = "?"        # from cat /etc/os-* down in the file dsinfo.txt 
    os_version = "NA"   # from cat /etc/os-* down in the file dsinfo.txt 
    uptime = 'NoInfo'  # setting a default value, in case we do not find it in the dsinfo.txt file
    full_os_text = os_type + '-' + os_version + ' / ' + dsi_os  # Generally we should be able to improve this initial default value
    hpv = mask = cpus = ram = ' ??   '
    manu = fam = pname = '...Unknown...'
    ip_match = ' inet ' + ip_add
    node_kernel = ""
    kernel_version = ""

    try:      ## after setting some default values, we see what the dsinfo.txt file has
        with open(node_dsinfo_filename, 'r') as inf:
            for line in inf:
                line = line.lstrip()
                if line.startswith("Operating System: "):
                    dsi_os = line.split(': ')[1].strip()
                    if dsi_os.lower().startswith('windows'):
                        dsi_os = dsi_os.split()[-1].strip(')')
                        break # no more info to be found in the restricted dsinfo.txt file for windows workers
                    if dsi_os.lower().startswith('suse'):
                        dsi_os = dsi_os.replace(' Linux Enterprise Server ','-')
                    if dsi_os.lower().startswith('red hat'):
                        if '.' in dsi_os:
                            dot_pos = dsi_os.find('.')
                            version = dsi_os[dot_pos - 1] + dsi_os[dot_pos + 1]
                            dsi_os = 'RHEL' + version
                        else:
                            dsi_os = 'RHEL'
                    if dsi_os.lower().startswith('rhel') :
                        dsi_os = 'RHEL'
                    if dsi_os.lower().startswith('centos'):
                        dsi_os = dsi_os.replace(' Linux ', '').rstrip('(Core)')
                    if dsi_os.lower().startswith('ubuntu'):
                        dsi_os = dsi_os.rstrip('LTS') 
                    if dsi_os.lower().startswith('oracle'):
                        dsi_os = dsi_os.replace(' Linux Server ','')
                    if dsi_os.lower().startswith('openshift'):
                        dsi_os = 'OpenShift'
                    continue
                if line.startswith("Kernel Version: "):
                    kernel_version = line.split(': ')[1].strip()
                    
                    continue
                ## further down the file we will start reading those lines (only for linux nodes!): 
                if line.startswith("Linux version "):
                    node_kernel = line.split()[2]
                    continue 
                if 'load average:' in line:
                    uptime = (line.split('up ')[1]).split(',')[0]
                    continue
                if line.startswith("NAME="):
                    os_type = line.split('="')[1].strip().strip('"')
                    if os_type.startswith("Red"):
                        os_type = "RHEL"         ## Just to make the output a little shorter
                    continue
                if line.startswith("VERSION="):
                    os_version = line.split('="')[1].strip('"').split()[0].strip('"')
                    continue 
                # but sometimes just a few lines later, we may encounter the correct info:
                if line.startswith('CentOS Linux release '):
                    os_type = 'Centos'
                    os_version = line.split()[3]
                    continue 
                if line.startswith('Red Hat Enterprise Linux release '):
                    os_type = 'Rhel'
                    os_version = line.split()[5]
                    continue 
                if line.startswith("Hypervisor vendor: "):
                    hpv = line.split(': ')[1].strip()
                    continue    
                if line.startswith("Manufacturer: "):
                    manu = line.split(': ')[1].strip()
                    continue
                if line.startswith("Product Name: "):
                    pname = line.split(': ')[1].strip()
                    continue
                if line.startswith("Family: "):
                    fam = line.split(': ')[1].strip()
                    continue       
                if ip_match in line:
                    try:           # we will just try to set the subnet-mask and stop reading the file
                        mask = line.split()[3].split('/')[1]
                    except :   # for the rare cases that the line will be malformed, still return a mask ??
                        pass # mask = '??'  # the initaly set value of mask is ?? already
                    break        # nothing else to look for in the dsinfo.txt file, we can stop reading its lines
            full_os_text = os_type + '-' + os_version + '/ ' + dsi_os
            debug_print(2, debug_level, f"...kernel_version={kernel_version}  node_kernel={node_kernel}")
            #return full_os_text, hpv, uptime, mask, node_kernel, manu, pname, fam
            return full_os_text, hpv, uptime, mask, kernel_version, manu, pname, fam

    except FileNotFoundError:        # for nodes that the SD did not gather info, at least return the default values
        return full_os_text, hpv, uptime, mask, node_kernel, manu, pname, fam

#---------------------------
# This method processes all the nodes
#---------------------------
def getnodes(f: str , opts: Options):
    node_tuples = []
    kernels_of_nodes = set()
    cnt_mke_nodes = 0
    cnt_mcr_nodes = 0
    cnt_msr_nodes = 0
    cnt_gpu_nodes = 0
    cnt_vcpus = 0

    with open(f, 'r') as r:
        sd = json.load(r)

    # runtime options (avoid globals)
    account_name = opts.accountname
    ticket_number = opts.ticketnumber
    bundle_path = opts.bundlepath
    bundle_date = opts.bundledate
    pretty = opts.pretty
    file_save = opts.filesave
    outputFile = opts.outputfile
    debug_level = opts.debug
    extended_output = opts.extended_output
    # -----------------------------------------------------------------------------
    # Output schema selection (kept compatible with legacy behavior)
    has_account = (account_name != '<undefined account name>')
    has_ticket = (ticket_number != '00000000')

    include_hw = (extended_output >= 1)

    if has_account and has_ticket:
        schema_mode = 'acct_ticket'
        header = 'ACCOUNT TICKET CLUSTER-ID HOSTNAME NODE-ID ROLE TYPE MCRv MKEv MSRv SWARM? KUBE? OS OSver ARCH HYPERV CPUs RAM GPU UPTIME AVAIL STATE IP/MASK COLLECT CREATED/UPDATED STATUS_MESSAGE BUNDLEDATE'
        if include_hw:
            header += ' MANUFACTURER PRODUCT_NAME FAMILY'
        sort_getter = itemgetter(5, 6, 3, 10)  # ROLE, TYPE, HOSTNAME, OS
        def build_row(**kw):
            return (kw['account_name'], kw['ticket_number'], kw['cluster_id'], kw['hostname'], kw['id'], kw['role'], kw['role_type'], kw['engver'], kw['ucpver'], kw['dtrver'],
                    kw['o_swarm'], kw['o_kube'], kw['os'], kw['os_string'], kw['arch'], kw['hypervisor'], kw['cpus'], kw['ram'], kw['gpu_mode'], kw['node_uptime'],
                    kw['avail'], kw['state'], kw['addr'], kw['collect'], kw['t_stamps'], kw['stsmsg'], kw['bundle_date']) + ((kw['manu'], kw['pname'], kw['fam']) if include_hw else ())

    elif has_account and not has_ticket:
        schema_mode = 'acct_only'
        header = 'ACCOUNT CLUSTER-ID HOSTNAME NODE-ID ROLE TYPE MCRv MKEv MSRv SWARM? KUBE? OS OSver ARCH HYPERV CPUs RAM GPU UPTIME AVAIL STATE IP/MASK COLLECT CREATED/UPDATED STATUS_MESSAGE BUNDLEDATE'
        if include_hw:
            header += ' MANUFACTURER PRODUCT_NAME FAMILY'
        sort_getter = itemgetter(4, 5, 2, 9)  # ROLE, TYPE, HOSTNAME, OS
        def build_row(**kw):
            return (kw['account_name'], kw['cluster_id'], kw['hostname'], kw['id'], kw['role'], kw['role_type'], kw['engver'], kw['ucpver'], kw['dtrver'],
                    kw['o_swarm'], kw['o_kube'], kw['os'], kw['os_string'], kw['arch'], kw['hypervisor'], kw['cpus'], kw['ram'], kw['gpu_mode'], kw['node_uptime'],
                    kw['avail'], kw['state'], kw['addr'], kw['collect'], kw['t_stamps'], kw['stsmsg'], kw['bundle_date']) + ((kw['manu'], kw['pname'], kw['fam']) if include_hw else ())

    elif (not has_account) and has_ticket:
        schema_mode = 'ticket_only'
        header = 'TICKET CLUSTER-ID HOSTNAME NODE-ID ROLE TYPE MCRv MKEv MSRver SWARM? KUBE? OS OSver ARCH HYPERV CPUs RAM GPU UPTIME AVAIL STATE IP/MASK COLLECT CREATED/UPDATED STATUS_MESSAGE BUNDLEDATE'
        if include_hw:
            header += ' MANUFACTURER PRODUCT_NAME FAMILY'
        sort_getter = itemgetter(4, 5, 2, 9)  # ROLE, TYPE, HOSTNAME, OS
        def build_row(**kw):
            return (kw['ticket_number'], kw['cluster_id'], kw['hostname'], kw['id'], kw['role'], kw['role_type'], kw['engver'], kw['ucpver'], kw['dtrver'],
                    kw['o_swarm'], kw['o_kube'], kw['os'], kw['os_string'], kw['arch'], kw['hypervisor'], kw['cpus'], kw['ram'], kw['gpu_mode'], kw['node_uptime'],
                    kw['avail'], kw['state'], kw['addr'], kw['collect'], kw['t_stamps'], kw['stsmsg'], kw['bundle_date']) + ((kw['manu'], kw['pname'], kw['fam']) if include_hw else ())

    else:
        schema_mode = 'minimal'
        header = 'CLUSTER-ID HOSTNAME NODE-ID ROLE TYPE MCRv MKEv MSRv SWARM? KUBE? OS OSver ARCH HYPERV CPUs RAM GPU UPTIME AVAIL STATE IP/MASK COLLECT CREATED/UPDATED STATUS_MESSAGE BUNDLEDATE'
        if include_hw:
            header += ' MANUFACTURER PRODUCT_NAME FAMILY'
        sort_getter = itemgetter(3, 4, 1, 8)  # legacy: ROLE, TYPE, HOSTNAME, (SWARM?)
        def build_row(**kw):
            return (kw['cluster_id'], kw['hostname'], kw['id'], kw['role'], kw['role_type'], kw['engver'], kw['ucpver'], kw['dtrver'],
                    kw['o_swarm'], kw['o_kube'], kw['os'], kw['os_string'], kw['arch'], kw['hypervisor'], kw['cpus'], kw['ram'], kw['gpu_mode'], kw['node_uptime'],
                    kw['avail'], kw['state'], kw['addr'], kw['collect'], kw['t_stamps'], kw['stsmsg'], kw['bundle_date'])  + ((kw['manu'], kw['pname'], kw['fam']) if include_hw else ())

    header_cols = header.split(' ')
    # -----------------------------------------------------------------------------
    
    
    for node in sd:
        hostname =  arch = os = os_string =  addr = node_uptime = cpus = "????"  # for windows nodes the value will remain like this
        cpus = "0"
        ram = "0"
        kernel_of_node = ""
        hypervisor = '-'
        role = "       "
        role_type = "    "
        id = "          "
        cpus = "     "
        ram = "    "
        addr = "???.???.???.???"
        subnet_mask = "??"
        manu = pname = fam = "...Unknown..."


    
        
        # Get the hostname if it is described
        if "Description" in node:
            if 'Hostname' in node['Description']:
                hostname = node['Description']['Hostname']
            else: # no hostname in the description so lets mark it with !!!'s and the nodeID in the output
                if "ID" in node:
                    trunc = node['ID'][:10]
                    hostname = f"!!! {trunc} ID!!!>>"
                

        # Get the unique ID of this node if it is present
        if "ID" in node:
            id = node['ID'][:10]
        else:
            continue # no ID in node

        # Get the role of this node
        if "Spec" in node:
            if node['Spec']['Role'] == 'manager':
                if "ManagerStatus" in node:
                    if 'Leader' in node['ManagerStatus'] and node['ManagerStatus']['Leader'] == True:
                        role = 'leader'
                        role_type = 'MKE '
                    else:
                        role = 'manager'
                        role_type = 'MKE '
                else:  # something went wrong during the bundle creation, says this is a manager but something crapped out...
                    role = 'BAD-Manager'
                    role_type = 'MKE '
            else:
                role = 'worker'
                role_type = 'MCR '
        
        
        
        # now we need to check if it is a bad manager and see if cpus and ram is present...
        if "Description" in node:
            if "Resources" in node['Description']:
                if "NanoCPUs" in node['Description']['Resources']:
                    # 1 CPU == 10⁹ NanoCPUs
                    nano_cpus = node['Description']['Resources']['NanoCPUs']
                    cpus = str(int(nano_cpus/1e9))
                    cnt_vcpus += int(nano_cpus/1e9)
                    if "MemoryBytes" in node['Description']['Resources']:
                        # 1 GiB == 1024³ bytes
                        total_ram = node['Description']['Resources']['MemoryBytes']
                        ram = str(round(total_ram/(1024**3), 2))
                    
        # now pad out the cpus and ram with spaces for output
        cpus += "     "
        ram += "    "
        
        if 'Architecture' in node['Description']['Platform']:
            arch = node['Description']['Platform']['Architecture']

        # Get the availability and state of this node.
        if "Spec" in node:
            if "Availability" in node['Spec']:
                avail = node['Spec']['Availability']
            else:
                avail = "unknown"
        if "Status" in node:
            if "State" in node['Status']:
                state = node['Status']['State']
            else:
                state = "unknown"

        # Get the IP address
        if "Status" in node:
            if 'Addr' in node['Status']:
                addr = node['Status']['Addr']
                if addr == '127.0.0.1' or addr == '0.0.0.0':  ## for some manager nodes we may have this, and we should correct 
                    # now verify that ManagerStatus is there, then check to make sure Addr is present too...
                    if "ManagerStatus" in node:
                        if "Addr" in node['ManagerStatus']:
                            addr = node['ManagerStatus']['Addr']
                            addr = addr.replace(':2377','')
        
        if "Description" in node:
            if "Platform" in node['Description']:
                if 'OS' in node['Description']['Platform']:
                    os = node['Description']['Platform']['OS']
                    # Now get the fully qualified OS string, the hypervisor, how long running, subnet mask, also the kernel of the node...
                    os_string, hypervisor, node_uptime, subnet_mask, kernel_of_node, manu, pname, fam = full_os_details_v1(hostname, addr, bundle_path, debug_level)
                    addr = ' / '.join([addr, subnet_mask])  # addr = addr + ' / ' + subnet_mask
                    #print(f"---kernel_of_node---{kernel_of_node}  ---hostname---{hostname}")
                    if kernel_of_node != "":
                        kernels_of_nodes.add(kernel_of_node)

        # Get the MCR version
        engver = "?.?.????"
        collect = "unknown"
        if "Description" in node:
            if "Engine" in node['Description']:
                if 'EngineVersion' in node['Description']['Engine']:
                    engver = node['Description']['Engine']['EngineVersion']
                if "Spec" in node:
                    if "Labels" in node['Spec']:
                        if "com.docker.ucp.access.label" in node['Spec']['Labels']:
                            collect = node['Spec']['Labels']['com.docker.ucp.access.label']
                        # here we can Display if swarm / kube orchestrator
                        # Display if swarm / kube orchestrator
                        o_swarm = o_kube = '-'
                        if 'com.docker.ucp.orchestrator.swarm' in node['Spec']['Labels'] and node['Spec']['Labels']['com.docker.ucp.orchestrator.swarm'] == 'true':
                            o_swarm = 'swarm '
                        else:
                            o_swarm = '------'
                        if 'com.docker.ucp.orchestrator.kubernetes' in node['Spec']['Labels'] and node['Spec']['Labels']['com.docker.ucp.orchestrator.kubernetes'] == 'true':
                            o_kube = 'kube  '
                        else:
                            o_kube = '------'
                        combined_orch = '/'.join([o_swarm, o_kube])

        

        # Get the status of the node.  I dont care about the status of this node....
        stsmsg = "N/A"
        if "Status" in node:
            if 'Message' in node['Status']:
                stsmsg = node['Status']['Message']
        
        # do we really need to display this column of versioning....  its redundant because i already do the VER column, why put the MCR-ver & MKE/MSR???
        # Get the MKE and MSR version numbers, and also append the /msrversion to the column MKE/MSR if MSR node
        ucpver = "?.?.??"
        dtrver = "?.?.??"
        if bundle_path != '.':
            dir_to_search2 = bundle_path 
            dir_to_search2 += hostname 
        else:
            dir_to_search2 = hostname 
        ucpver     = getddcver(dir_to_search2,'ucp-proxy.txt','IMAGE_VERSION')
        if ucpver == '-':
            ucpver = '?.?.??'
        dtrver     = getddcver(dir_to_search2,'dtr-registry-*.txt','DTR_VERSION')
        if dtrver == '-':
            dtrver = '-.-.--'

        if dtrver != '-.-.--':
            role_type = 'MSR '

        if bundle_path != '.':
            path_to_search = bundle_path 
            path_to_search += 'ucp-instance-id.txt' 
        else:
            path_to_search = 'ucp-instance-id.txt'
        file_path = Path(path_to_search)
        
        cluster_id = '0000000000'
        if file_path.is_file():
            try:
            # .read_text() returns whole file; .strip() removes newline
                cluster_id = file_path.read_text(encoding='utf-8').strip()
            except Exception as e:
                cluster_id = '00-??-000'
        # truncate to ten characters
        cluster_id =cluster_id[:10]

        c_at = "1970-01-01T00:00:00.0000000Z"
        u_at = "1970-01-01T00:00:00.0000000Z"
        # Get when this node was created and last updated.
        if "CreatedAt" in node:
            c_at = node['CreatedAt'].split('.')[0].replace("T","_")
        if "UpdatedAt" in node:
            u_at = node['UpdatedAt'].split('.')[0].replace("T","_")
        t_stamps = ' / '.join([c_at,u_at])
        
        #ucpver,dtrver, engver
        match role_type:
            case "MKE ":
                disp_ver = ucpver
            case "MCR ":
                disp_ver = engver
            case "MSR ":
                disp_ver = dtrver 

        debug_print(2, debug_level, f"role_type={role_type}, engver={engver}    ucpver={ucpver}    dtrver={dtrver} ")

        # this expects a fully qualified path to the file kube-describe-node.txt which is in the root directory of the bundle
        # for example "docker-support-wb4gjlv-20250723-07_53_35/kube-describe-node.txt"
        # 
        #-------------------------------------------------------------------------------------
        kubedescribe_file  = bundle_path 
        kubedescribe_file += 'kube-describe-nodes.txt'
        nodehostname = hostname.split('.', 1)[0]
        
        gpu = 0
        gpu = parse_node_gpu_flag( kubedescribe_file, nodehostname )
        
        if gpu:
            gpu_mode = 'GPU '
        else:
            gpu_mode = '... '

        
        

        # Build the output row once per node (schema selected above)
        node_tuples.append(build_row(account_name=account_name, ticket_number=ticket_number, cluster_id=cluster_id, hostname=hostname, id=id, role=role, role_type=role_type, disp_ver=disp_ver, engver=engver, ucpver=ucpver, dtrver=dtrver, o_swarm=o_swarm, o_kube=o_kube, os=os, os_string=os_string, arch=arch, hypervisor=hypervisor, cpus=cpus, ram=ram, gpu_mode=gpu_mode, node_uptime=node_uptime, avail=avail, state=state, addr=addr, collect=collect, t_stamps=t_stamps, stsmsg=stsmsg, bundle_date=bundle_date, manu=manu, pname=pname, fam=fam))

        match role_type:
            case "MKE ":
                cnt_mke_nodes += 1
            case "MCR ":
                cnt_mcr_nodes += 1
            case "MSR ":
                cnt_msr_nodes += 1
        if gpu:
            cnt_gpu_nodes += 1
    
    # Sort and compute column widths once (legacy code recomputed this inside the node loop)
    s = sorted(node_tuples, key=sort_getter) if node_tuples else []
    w = []
    if node_tuples:
        for i in range(len(node_tuples[0])):
            longest_value_in_col_i = max(s, key=lambda row: len(str(row[i])))[i]
            w.append(len(str(longest_value_in_col_i)))
    else:
        # Edge case: no rows found; still print a header safely
        w = [len(c) for c in header_cols]

    if file_save:
        with open(outputFile, 'w') as outfile:
            # 2) print & write the header
            row_print2(header_cols, w, outfile=outfile, pretty=pretty)
            # 3) print & write each data row
            for row in s:
                row_print2(row, w, outfile=outfile, pretty=pretty)
    else:
        row_print2(header_cols, w, outfile=None, pretty=pretty)
        for row in s:
            row_print2(row, w, outfile=None, pretty=pretty)

    
    print(f"--------------------------------------------------------------------------\n🔶🔶 SUMMARY INFORMATION 🔶🔶", flush=True)
    print(f"Node Counts:  MKE:[{cnt_mke_nodes}]   MCR:[{cnt_mcr_nodes}]   MSR:[{cnt_msr_nodes}]   vCPU:[{cnt_vcpus}]\n", flush=True)
    print(f"Unique OS kernels discovered [{len(kernels_of_nodes)}]\n{format(kernels_of_nodes)}\n---------------------------------------------------", flush=True)
        

    

#---------------------------
# These methods simply validates the command line date/time format is correct, if specified
#---------------------------
def normalize_timestamp(ts: str) -> str:
    """
    Ensure ts is in the form 'DD/MM/YYYY, hh:mm'.
    If no ', hh:mm' is present or time is invalid, append/fix to '00:00'.
    """
    parts = ts.split(",", 1)
    date_part = parts[0].strip()

    # see if there's a time fragment
    if len(parts) == 2:
        time_candidate = parts[1].strip()
        if re.fullmatch(r"\d{2}:\d{2}", time_candidate):
            return f"{date_part}, {time_candidate}"
        else:
            print(f"Warning: time '{time_candidate}' is invalid, defaulting to '00:00'")
    # if we fell through (no time or bad time)…
    return f"{date_part}, 00:00"
#---------------------------
def validate_date(date_str: str) -> bool:
    """Return True if date_str is a valid calendar date in DD/MM/YYYY."""
    if not re.fullmatch(r"\d{2}/\d{2}/\d{4}", date_str):
        print("❌ Error: Date must be in DD/MM/YYYY format (e.g. 07/03/2025).")
        return False

    day_s, mon_s, yr_s = date_str.split("/")
    day, mon, yr = int(day_s), int(mon_s), int(yr_s)

    if not (1 <= day <= 31):
        print(f"❌ Error: Day '{day_s}' is out of range (01–31).")
        return False
    if not (1 <= mon <= 12):
        print(f"❌ Error: Month '{mon_s}' is out of range (01–12).")
        return False

    try:
        datetime(yr, mon, day)
    except ValueError as e:
        print(f"❌ Error: Invalid calendar date: {e}")
        return False

    return True
#---------------------------
def validate_timestamp(ts: str) -> bool:
    """
    Normalize ts → 'DD/MM/YYYY, hh:mm', then validate the date portion.
    """
    norm = normalize_timestamp(ts)
    #print(f"Normalized → '{norm}'")
    date_part = norm.split(",", 1)[0].strip()
    return validate_date(date_part)
#---------------------------
def validate_ddmmyyyy(date_str: str) -> bool:
    """
    Return True if date_str (DD/MM/YYYY) is valid.
    """
    if not re.fullmatch(r"\d{2}/\d{2}/\d{4}", date_str):
        print("❌ Error: Date must be DD/MM/YYYY.")
        return False

    day, mon, yr = map(int, date_str.split("/"))
    if not (1 <= day <= 31):
        print(f"❌ Error: Day {day:02d} out of range.")
        return False
    if not (1 <= mon <= 12):
        print(f"❌ Error: Month {mon:02d} out of range.")
        return False

    try:
        datetime(yr, mon, day)
    except ValueError as e:
        print(f"❌ Error: Invalid date: {e}")
        return False

    return True
#---------------------------
def ensure_timestamp(ts: str) -> str:
    """
    Ensure ts contains a time.  
    - If there is no comma/time, append ', 00:00'.  
    - If there *is* a comma but the hh:mm is malformed, overwrite with ', 00:00'.  
    Returns the normalized string.
    """
    if "," not in ts:
        return f"{ts.strip()}, 00:00"

    date_part, time_part = ts.split(",", 1)
    time_part = time_part.strip()

    # valid time is exactly HH:MM
    if re.fullmatch(r"[0-2]\d:[0-5]\d", time_part):
        return f"{date_part.strip()}, {time_part}"
    else:
        # malformed time
        return f"{date_part.strip()}, 00:00"
#---------------------------
def normalize_and_validate(ts: str) -> str:
    """
    Normalize ts to include time and validate the date portion.
    Returns the normalized timestamp on success, or raises ValueError.
    """
    
    normalized = ensure_timestamp(ts)
    
    date_part = normalized.split(",", 1)[0].strip()

    if not validate_ddmmyyyy(date_part):
        raise ValueError(f"❌ Invalid date portion: '{date_part}'")

    return normalized

# -----------------------------------------------------------------------------------
#if __name__ == "__main__":
def _handle_sigterm(signum, frame):
    raise KeyboardInterrupt


def _handle_top_level_interrupt() -> int:
    print("\n[sdnodes] interrupted — exiting gracefully")
    return 130


def cli_main() -> int:
    # Set up argument parser
    parser = argparse.ArgumentParser(description="SDNODES Version: 1.12  Command line input enabled with:")
    parser.add_argument("--pretty", type=int, choices=[0, 1], default=1, help="Set pretty level: 1=On (Default: no delimiters) 0=Off(Use a semicolon (;) as delimiter to enable import to spreadsheet)")
    parser.add_argument("--outputfile", type=str, default='nodes_output.csv', help="Output file name (e.g., test.csv) -- (default = nodes_output.csv), can have a fully qualified path and filenamefor placement, else placed into pwd ")
    parser.add_argument("--filesave", type=int, choices=[0,1], default=0, help="Turn on saving to output file. Default=0 disabled. If enabled see --outputfile")
    parser.add_argument("--accountname", type=str, default='<undefined account name>', help="Used to supply an Account Name if desired. Default = <undefined account name>. If using spaces in the Account Name be sure to enclose them in double quotes ")
    parser.add_argument("--ticketnumber", type=str, default='00000000', help="Used if you want to show output associated specifically with a ticket number. Default = 00000000" )
    parser.add_argument("--bundlepath", type=str, default='.', help="Path to where support bundle resides. Default = .  ")
    parser.add_argument("--bundledate", type=str, default=None, help="Simple date of support bundle. Format: dd/mm/YYYY   Default=today")
    parser.add_argument("--bundlecreatedate", type=str, default='', help="Extended date of support bundle. Any string, preferred style: 2025-07-21T06:51:40.000Z  Default = '' ")
    parser.add_argument("--debug", type=int, choices=[0,1,2,3,4], default=0, help="Debug level: 0=off (default) up to 4=very verbose")
    parser.add_argument("--extended-output", type=int, choices=[0, 1, 2, 3, 4], default=0, help="Extended output level: 0=baseline (default) up to 4=most detailed, for now if >= 1 then displays hardware info")

    args = parser.parse_args()
    # time.sleep(7) just a simple test to delay so I can test the multiapp functions within the console tab windows... 
    debug_level = args.debug

    extended_output = args.extended_output
    pretty = args.pretty
    if pretty == 0:
        print("Pretty = False, using semicolon delimiter")
    
    outputFile = args.outputfile
    file_save = args.filesave
    if file_save == 1:
        print(f"Saving output to: {outputFile}")
    
    account_name = args.accountname
    if account_name != '<undefined account name>':
        account_name = f"{account_name:<9}" #pad it out with spaces to a minimum of 9 chars, will make pretty output lineup.
        print(f"Using AccountName: {account_name}")
    
    ticket_number = args.ticketnumber 
    if ticket_number != '00000000':
        ticket_number = f"{ticket_number:<9}" #pad it out with spaces to be minimum of 9 chars, will make pretty output line up.
        print(f"Using Ticket Number: {ticket_number}")

    bundle_path = args.bundlepath 
    if bundle_path != '.':
        if not bundle_path.endswith('/'):
            bundle_path += '/'   
        bundle_file = bundle_path 
        bundle_file += ucp_nodes 
        print(f"Using Bundle Path: {bundle_path}") 
    else:
        bundle_file = ucp_nodes 
    
    
    bundle_date = datetime.now().strftime("%d/%m/%Y")
    if args.bundledate is not None:
        bundle_date = args.bundledate
    elif args.bundlecreatedate != '':
        bundle_date = args.bundlecreatedate
    else:
        bundle_date = datetime.now().strftime("%d/%m/%Y")
    print(f"Using bundle create date {bundle_date}")

    

    #bundle_date = datetime.now().strftime("%d/%m/%Y")
    #if args.bundledate is None:
    #    if args.bundlecreatedate == '':
    #        bundle_date = datetime.now().strftime("%d/%m/%Y")
    #        #bundle_date = '2020-01-31T00:01:01.000Z'
    #    else:
    #        bundle_date = args.bundlecreatedate
    #        print(f"Using bundle create date {bundle_date}")



    # Consolidate runtime options (avoid module-level globals)
    opts = Options(
        pretty=(pretty != 0),
        filesave=(file_save == 1),
        outputfile=outputFile,
        accountname=account_name,
        ticketnumber=ticket_number,
        bundlepath=bundle_path,
        bundledate=bundle_date,
        debug=debug_level,
        extended_output=extended_output,
    )

    # start duration timer....
    #start_time = time.time()

    # Check to make sure this is a cluster bundle by trying to find ucp_nodes.txt
    if not os.path.isfile(bundle_file):
        print(f"❌ NOT valid cluster bundle, file '{bundle_file}' not found, exiting")
        return 2
    else: # Process the full support bundle
        getnodes(bundle_file, opts)
    
    # stop duration timer
    #end_time = time.time()
    #elapsed_time = end_time - start_time
    #hours = int(elapsed_time // 3600)
    #minutes = int((elapsed_time % 3600) // 60)
    #seconds = int(elapsed_time % 60)
    #print(f"Elapsed Time: {hours} hours, {minutes} minutes, and {seconds} seconds")
    # print("⚠️  (warning sign)\n❗  (heavy exclamation)\n🚧  (construction)\n🔶  (large orange diamond)\n[!] (ASCII warning)\n(!) (ASCII warning)")

    
if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        raise SystemExit(cli_main())
    except KeyboardInterrupt:
        raise SystemExit(_handle_top_level_interrupt())