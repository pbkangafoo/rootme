#!/usr/bin/env python
# -*- coding: utf8 -*-

"""


	 ██▀███   ▒█████   ▒█████  ▄▄▄█████▓ ███▄ ▄███▓▓█████ 
	▓██ ▒ ██▒▒██▒  ██▒▒██▒  ██▒▓  ██▒ ▓▒▓██▒▀█▀ ██▒▓█   ▀ 
	▓██ ░▄█ ▒▒██░  ██▒▒██░  ██▒▒ ▓██░ ▒░▓██    ▓██░▒███   
	▒██▀▀█▄  ▒██   ██░▒██   ██░░ ▓██▓ ░ ▒██    ▒██ ▒▓█  ▄ 
	░██▓ ▒██▒░ ████▓▒░░ ████▓▒░  ▒██▒ ░ ▒██▒   ░██▒░▒████▒
	░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░▒░▒░   ▒ ░░   ░ ▒░   ░  ░░░ ▒░ ░
	 ░▒ ░ ▒░  ░ ▒ ▒░   ░ ▒ ▒░     ░    ░  ░      ░ ░ ░  ░
	 ░░   ░ ░ ░ ░ ▒  ░ ░ ░ ▒    ░      ░      ░      ░   
	 ░         ░ ░      ░ ░                  ░      ░  ░
   
		ROOTME	-	version 0.1
		
		Written by Peter Bartels
		
		https://www.kangafoo.de
		
		ROOTME is a little useful post exploitation tool which suggests
		local kernel exploits based on the version.
        
        Initial pre-release, some functionality is still missing.
        Database will be extended.


"""

import sys
import argparse
import os
import platform
import json


#database for vulnerable kernels, perhaps extern file in future?
datadb = '''
[
    {
        "name" : "PTRACE_TRACEME local root",
        "description" : "Linux Kernel 4.10 < 5.1.17 - PTRACE_TRACEME pkexec Local Privilege Escalation",
        "cve" : "2019-13272",
        "details" : "https://bugs.chromium.org/p/project-zero/issues/detail?id=1903",
        "download" : "https://raw.githubusercontent.com/jas502n/CVE-2019-13272/master/CVE-2019-13272.c",
        "language" : "c",
        "minver" : "4.10",
        "maxver" : "5.1.17"
    },
    {
        "name" : "io_uring Offload of sendmsg()",
        "description" : "Linux 5.3 - Privilege Escalation via io_uring Offload of sendmsg() onto Kernel Thread with Kernel Creds",
        "cve" : "2019-19241",
        "details" : "https://bugs.chromium.org/p/project-zero/issues/detail?id=1975",
        "download" : "https://dl.packetstormsecurity.net/1912-exploits/GS20191216153944.txt",
        "language" : "c",
        "minver" : "5.3",
        "maxver" : "5.4.2"
    },
    {
        "name" : "map_write() CAP_SYS_ADMIN",
        "description" : "Linux Kernel 4.15.x - 4.19.2 - map_write() CAP_SYS_ADMIN Local Privilege Escalation (dbus Method)",
        "cve" : "2018-18955",
        "details" : "http://www.securityfocus.com/bid/105941",
        "download" : "https://www.exploit-db.com/download/47165",
        "language" : "bash",
        "minver" : "4.15.0",
        "maxver" : "4.19.1"
    },
    {
        "name" : "mq_notify: double sock_put()",
        "description" : "Linux Kernel 2.6.0 - 4.11.8 - mq_notify double sock_put() Local Privilege Escalation",
        "cve" : "2017-11176",
        "details" : "https://www.securityfocus.com/bid/99919",
        "download" : "https://www.exploit-db.com/download/45553",
        "language" : "c",
        "minver" : "2.6.0",
        "maxver" : "4.11.9"
    },
    {
        "name" : "local memory corruption vulnerability",
        "description" : "Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation",
        "cve" : "2017-16995",
        "details" : "https://www.securityfocus.com/bid/102288",
        "download" : "https://www.exploit-db.com/download/45010",
        "language" : "c",
        "minver" : "2.6.0",
        "maxver" : "4.14.6"
    }
]'''


def clear():
    """
    
    clear() -> no return
    
    just clear screen for linux and windows
    
    """
    os.system("cls" if os.name == "nt" else "clear")	



def get_filename(url):
    """
    
    get_filename(string) -> string

    extracts the filename from a given url
    
    """
    pos = (url.rfind('/')+1)
    return url[pos:]



def download_file(url):
    """

    download_file(string) -> no return
    
    downloads a file from a given url and stores it with the same name
    
    """
    




def get_kernel_version():
    """
    
    get_kernel_version() -> string
    
    returns the version of kernel, equal to uname -r
    
    """
    kernel = ""
    kernel = platform.release()
    kernel = kernel[0:kernel.find('-')]
    return kernel



def version_to_tuple(version):
    """
    
    version_to_tuple(string) -> tuple
    
    converts a version as string to tuple, to make versions comparable
    
    string to tuple: https://www.codespeedy.com/comma-separated-string-to-tuple-in-python/
    
    """
    splitted = []
    if version != "":
        for subnum in version.split('.'):
            splitted.append(int(subnum))
    return tuple(splitted)



def is_vulnerable(myversion,minversion,maxversion):
    """

    is_vulnerable(tuple,tuple,tuple) -> boolean
    
    function checks whether a given kernel version is in a certain range of vulnerable kernel versions

    """
    if ((minversion <= myversion) and (maxversion >= myversion)):
        return True
    else:
        return False


def check_for_vuln(myversion,mydb):
    """

    check_for_vuln(tuple,json) -> no return, just output

    Function checks the given kernel version against the database looking for potential exploits
    
    """
    for item in mydb:
        if is_vulnerable(myversion,version_to_tuple(item['minver']),version_to_tuple(item['maxver'])):
            print("\n[~] Name: "+item['name']+" (CVE: "+item['cve']+")")
            print("[~] Description: "+item['description'])
            print("[~] Details: "+item['details'])
            print("[~] Download: "+item['download'])
            #print(" -- "+get_filename(item['download']))


def infoheader():
    """
    
    infoheader() -> no return
    
    prints header logo and avatar target name and CID
    
    """
    clear()
    print(" ██▀███   ▒█████   ▒█████  ▄▄▄█████▓ ███▄ ▄███▓▓█████ ")
    print("▓██ ▒ ██▒▒██▒  ██▒▒██▒  ██▒▓  ██▒ ▓▒▓██▒▀█▀ ██▒▓█   ▀ ")
    print("▓██ ░▄█ ▒▒██░  ██▒▒██░  ██▒▒ ▓██░ ▒░▓██    ▓██░▒███   ")
    print("▒██▀▀█▄  ▒██   ██░▒██   ██░░ ▓██▓ ░ ▒██    ▒██ ▒▓█  ▄ ")
    print("░██▓ ▒██▒░ ████▓▒░░ ████▓▒░  ▒██▒ ░ ▒██▒   ░██▒░▒████▒")
    print("░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░▒░▒░   ▒ ░░   ░ ▒░   ░  ░░░ ▒░ ░")
    print(" ░▒ ░ ▒░  ░ ▒ ▒░   ░ ▒ ▒░     ░    ░  ░      ░ ░ ░  ░ ")
    print(" ░░   ░ ░ ░ ░ ▒  ░ ░ ░ ▒    ░      ░      ░      ░    ")
    print(" ░         ░ ░      ░ ░                  ░      ░  ░\n")



if __name__=="__main__":
    parser = argparse.ArgumentParser("%prog [options] arg1 arg2")
    parser.add_argument("-d", "--detect", dest="detect",default=False, action="store_true",help="automatically gets the kernel version")
    parser.add_argument("-m", "--manual", dest="manual",default="0.0.0",help="specify the kernel version e.g. 2.6.18")
    #parser.add_argument("-g", "--get",dest="getfile",default=False, action="store_true",help="downloads exploits when enabled")
    options = parser.parse_args()
    if len(sys.argv) < 2:
        infoheader()
        parser.print_help()
        quit()
    else:
        detect = options.detect
        kernel = options.manual
        #getfile = options.getfile
        dbase = json.loads(datadb)
        infoheader()
        print("[~] Exploits in DB: "+str(len(dbase)))
        if options.detect:
            detected_kernel = get_kernel_version()
            print("[~] Kernel version found: "+detected_kernel)
            check_for_vuln(version_to_tuple(detected_kernel),dbase)
        elif kernel != "0.0.0":
            print("[~] Kernel version given: "+kernel)
            check_for_vuln(version_to_tuple(kernel),dbase)