#!/usr/bin/env python3

# #Domain name enumeration tool that leverages awesome tools:
#     - Sublist3r by Ahmed Aboul-Ela (https://github.com/aboul3la/Sublist3r)
#     - enumall by Jason Haddix (https://github.com/jhaddix/domain)
#     - Knock by Gianni Amato (https://github.com/guelfoweb/knock)
#     - Subbrute by TheRook (https://github.com/TheRook/subbrute)
#     - massdns by B. Blechschmidt (https://github.com/blechschmidt/massdns)
#     - Amass by Jeff by Foley (https://github.com/OWASP/Amass)
#     - SubFinder by Ice3man543 (https://github.com/subfinder/subfinder)
#     - Recon-ng by Tim Tomes (LaNMaSteR53) (https://bitbucket.org/LaNMaSteR53/recon-ng)
#     - EyeWitness by ChrisTruncer (https://github.com/FortyNorthSecurity/EyeWitness)
#     - SecList (DNS Recon List) by Daniel Miessler (https://github.com/danielmiessler/SecLists)
#     - LevelUp All.txt Subdomain List by Jason Haddix

# # Github - https://github.com/cakinney (Caleb Kinney)

import argparse
import csv
import datetime
import glob
import os
import urllib

import requests
import subprocess
import time
from signal import signal, alarm, SIGALRM
import re

today = datetime.date.today()


def get_args():
    parser = argparse.ArgumentParser(description="domained")
    parser.add_argument(
        "-d", "--domain", type=str, help="Domain", required=False, default=False
    )
    parser.add_argument(
        "-s",
        "--secure",
        help="Secure",
        action="store_true",
        required=False,
        default=False,
    )
    parser.add_argument(
        "-b", "--bruteforce", help="Bruceforce", action="store_true", default=False
    )
    parser.add_argument("--upgrade", help="Upgrade", action="store_true", default=False)
    parser.add_argument("--install", help="Install", action="store_true", default=False)
    parser.add_argument("--vpn", help="VPN Check", action="store_true", default=False)
    parser.add_argument(
        "-p", "--ports", help="Ports", action="store_true", default=False
    )
    parser.add_argument(
        "-q", "--quick", help="Quick", action="store_true", default=False
    )
    parser.add_argument(
        "--bruteall", help="Bruteforce JHaddix All", action="store_true", default=False
    )
    parser.add_argument(
        "-a","--altdns", help="using altdns", action="store_true", default=False
    )
    parser.add_argument(
        "--notify", help="Notify when script completed", nargs="?", default=False
    )
    parser.add_argument(
        "--active", help="EyeWitness Active Scan", action="store_true", default=False
    )
    parser.add_argument(
        "--noeyewitness", help="No EyeWitness", action="store_true", default=False
    )

    return parser.parse_args()






def banner():
    print(
        """\033[1;31m
         ___/ /__  __ _  ___ _(_)__  ___ ___/ /
        / _  / _ \/  ' \/ _ `/ / _ \/ -_) _  /
        \_,_/\___/_/_/_/\_,_/_/_//_/\__/\_,_/
    \033[1;34m\t\t\tgithub.com/cakinney\033[1;m"""
    )
    globpath = "*.csv"
    globpath2 = "*.lst"
    if (next(glob.iglob(globpath), None)) or (next(glob.iglob(globpath2), None)):
        print("\nThe following files may be left over from failed domained attempts:")
        for file in glob.glob(globpath):
            log("  - {}".format(file))
        for file in glob.glob(globpath2):
            log("  - {}".format(file))
        signal(SIGALRM, lambda x: 1 / 0)
        try:
            alarm(5)
            RemoveQ = input("\nWould you like to remove the files? [y/n]: ")
            if RemoveQ.lower() == "y":
                os.system("rm *.csv")
                os.system("rm *.lst")
                log("\nFiles removed\nStarting domained...")
                time.sleep(5)
            else:
                log("\nThank you.\nPlease wait...")
                time.sleep(1)
        except:
            log("\n\nStarting domained...")


def extractip():
    f = open(massdnsoutput,"r")
    s = f.read()
    ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', s)
    ip = set(ip)
    write = open(iplist,'w')
    for x in ip:
        write.write(x+'\n')
    f.close()
    read = open(iplist,'r')
    lines = read.readlines()
    ipset = set(lines)
    for ip in ipset:
        write.write(ip+'\n')
    write.close()


def runProcess(exe):
    p = subprocess.Popen(exe, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while(True):
        # returns None while subprocess is running
        retcode = p.poll()
        line = p.stdout.readline()
        yield line
        if retcode is not None:
            break

def run(exe):
    for line in runProcess(exe.split()):
        line = line.strip()
        print(line)
        logfile.write(line)
        logfile.write('\n')


def log(string):
    print(string)
    logfile.write(string)


def sublist3r(brute=False):
    log("\n\n\033[1;31mRunning Sublist3r \n\033[1;37m")
    sublist3rFileName = "{}_sublist3r.txt".format(output_base)
    Subcmd = "python {} -v -t 15 {} -d {} -o {}".format(
        os.path.join(script_path, "bin/Sublist3r/sublist3r.py"),
        "-b" if brute else "",
        domain,
        sublist3rFileName,
    )
    log("\n\033[1;31mRunning Command: \033[1;37m{}".format(Subcmd))
    # os.system(Subcmd)
    run(Subcmd)
    log("\n\033[1;31mSublist3r Complete\033[1;37m")
    time.sleep(1)



def checkresponse(file):
    log("\n\n\033[1;31mchecking Responsive domains \n\033[1;37m")
    r = open(file,"r")
    lines = r.readlines()
    lines = [x.strip() for x in lines]
    w = open(responsivefile,"w")
    for line in lines:
        if urllib.urlopen(line).getcode() not in {403,500,401,405,502}:
            w.write(line+"\n")
    w.close()


def nmap():
    log("\n\n\033[1;31mRunning nmap \n\033[1;37m")
    r = open(iplist,"r")
    lines= r.readlines()
    lines = [x.strip() for x in lines]
    w = open(ipscanningfile,"w")
    for ip in lines:
        w.write("<div style=\"font-family: 'Mina', serif;\"><h1>Nmap {} Results</h1></div>\n".format(ip))
        w.write("<pre>\n")
        nmapcommand = "nmap -sV -T3 -Pn -p3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443 {} >> {}".format(
            ip,
            ipscanningfile
        )
        run(nmapcommand)
        log(nmapcommand)
        w.write("</pre></div>\n")
    w.close()
    r.close()

def enumall():
    log("\n\n\033[1;31mRunning Enumall \n\033[1;37m")
    enumallCMD = "python {} {}".format(
        os.path.join(script_path, "bin/domain/enumall.py"), domain
    )
    log("\n\033[1;31mRunning Command: \033[1;37m{}".format(enumallCMD))
    # os.system(enumallCMD)
    run(enumallCMD)
    log("\n\033[1;31menumall Complete\033[1;37m")
    time.sleep(1)


def massdns():
    log("\n\n\033[1;31mRunning massdns \n\033[1;37m")
    # word_file = os.path.join(
    #     script_path, "bin/sublst/all.txt" if bruteall else "bin/sublst/sl-domains.txt"
    # )
    # massdnsCMD = "python {} {} {} | {} -r resolvers.txt -t A -o S -w {}-massdns.txt".format(
    #     os.path.join(script_path, "bin/subbrute/subbrute.py"),
    #     word_file,
    #     domain,
    #     os.path.join(script_path, "bin/massdns/bin/massdns"),
    #     output_base,
    # )

    massdnsCMD = "{} -r resolvers.txt -t A -o S -w {} {}".format(
        os.path.join(script_path, "bin/massdns/bin/massdns"),
        massdnsoutput,
        subdomainUniqueFile
        )
    log("\n\033[1;31mRunning Command: \033[1;37m{}".format(massdnsCMD))
    # os.system(massdnsCMD)
    run(massdnsCMD)
    log("\n\033[1;31mMasscan Complete\033[1;37m")
    time.sleep(1)


def knockpy():
    log("\n\n\033[1;31mRunning Knock \n\033[1;37m")
    knockpyCmd = "python {} -c {} ".format(
        os.path.join(script_path, "bin/knockpy/knockpy/knockpy.py"),
        domain,
    )
    log("\n\033[1;31mRunning Command: \033[1;37m {}".format(knockpyCmd))
    # os.system(knockpyCmd)
    run(knockpyCmd)
    rootdomainStrip = domain.replace(".", "_")
    knockpyFilenameInit = "{}_knock.csv".format(output_base)
    os.system("mv {}* {}".format(rootdomainStrip, knockpyFilenameInit))
    time.sleep(1)
    knockpySubs = []
    knockpyipset = set()
    try:
        with open(knockpyFilenameInit, "rb") as f:
            reader = csv.reader(f, delimiter=",")
            for row in reader:
                knockpySubs.append(row[3])
                knockpyipset.update(row[1])
        f2 = open(iplist,'w')
        for ip in knockpyipset:
            f2.write(ip+'\n')
        filenameKnocktxt = "{}.txt".format(knockpyFilenameInit)
        f1 = open(filenameKnocktxt, "w")
        for hosts in knockpySubs:
            hosts = "".join(hosts)
            f1.writelines("\n" + hosts)
        f1.close()
        f2.close()
    except:
        log("\nKnock File Error\n")
    time.sleep(1)


def amass():
    log("\n\n\033[1;31mRunning Amass \n\033[1;37m")
    amassFileName = "{}_amass.txt".format(output_base)
    if bruteforce:
        amassCmd = "/root/go/bin/amass -brute -w {} -min-for-recursive 3  -d {} -o {} ".format(
            word_file,
            domain,
            amassFileName)
    else:  amassCmd = "/root/go/bin/amass  -min-for-recursive 3  -d {} -o {} ".format(
            domain,
            amassFileName)
    w = open(amassFileName,"w")
    w.close()
    log("\n\033[1;31mRunning Command: \033[1;37m{}".format(amassCmd))
    # os.system(amassCmd)
    run(amassCmd)
    log("\n\033[1;31mAmass Complete\033[1;37m")
    time.sleep(1)


def subfinder():
    log("\n\n\033[1;31mRunning Subfinder \n\033[1;37m")
    subfinderFileName = "{}_subfinder.txt".format(output_base)
    subfinderCmd = "/root/go/src/github.com/subfinder/subfinder/subfinder  -d {} -o {} -t 50 -v".format(
            domain,
             subfinderFileName)
    log("\n\033[1;31mRunning Command: \033[1;37m{}".format(subfinderCmd))
    # os.system(subfinderCmd)
    run(subfinderCmd)
    log("\n\033[1;31msubfinder Complete\033[1;37m")
    time.sleep(1)

def altdns(filename):
    log("\n\n\033[1;31mRunning Altdns \n\033[1;37m")
    altdnsFileName = "{}_altdns.txt".format(output_base)
    altdnsCmd = ".{} -i {}  -w {}  -o /tmp/altdnspermutation.txt -r  -s {}".format(
        os.path.join(script_path,"/bin/altdns/altdns.py"),
        filename,
        os.path.join(script_path,"bin/altdns/words.txt"),
        altdnsFileName
    )
    w1 = open(iplist,'w')
    w2 = open(subdomainAllFile,'w')
    r = open(altdnsFileName,'r')
    contents =  r.readlines()
    for line in contents:
        line = line.split(':')
        w1.write(line[1]+'\n')
        w2.write(line[0]+'\n')
    log("\n\033[1;31mRunning Command: \033[1;37m{}".format(altdnsCmd))
    # os.system(altdnsCmd)
    run(altdnsCmd)
    log("\n\033[1;31mAltdns Complete\033[1;37m")
    time.sleep(1)
    w1.close()
    r.close()
    w2.close()

def addingaltdns():
    # writeFiles("altdns")
    allinone()


def eyewitness(filename):
    log("\n\n\033[1;31mRunning EyeWitness  \n\033[1;37m")
    EWHTTPScriptIPS = "python {} -f {} {} --no-prompt --web  -d {}-{}-EW".format(
        os.path.join(script_path, "bin/EyeWitness/EyeWitness.py"),
        filename,
        "--active-scan" if active else "",
        output_base,
        time.strftime("%m-%d-%y-%H-%M"),
    )
    if vpn:
        log(
            "\n\033[1;31mIf not connected to VPN manually run the following command on reconnect:\n\033[1;37m{}".format(
                EWHTTPScriptIPS
            )
        )
        vpncheck()
    log("\n\033[1;31mRunning Command: \033[1;37m{}".format(EWHTTPScriptIPS))
    os.system(EWHTTPScriptIPS)
    log("\a")


def upgradeFiles():
    binpath = os.path.join(script_path, "bin")
    old_wd = os.getcwd()
    if not os.path.exists(binpath):
        os.makedirs(binpath)
    else:
        log("Removing old bin directory: {}".format(binpath))
        os.system("rm -rf {}".format(binpath))
        os.makedirs(binpath)
    log("Changing into domained home: {}".format(script_path))
    os.chdir(script_path)
    unameChk = str(subprocess.check_output(["uname", "-am"]))
    if "kali" not in unameChk:
        log("\n\033[1;31mKali Linux Recommended!\033[1;37m")
        time.sleep(1)
    sublist3rUpgrade = (
        "git clone https://github.com/aboul3la/Sublist3r.git ./bin/Sublist3r"
    )
    log("\n\033[1;31mInstalling Sublist3r \033[1;37m")
    os.system(sublist3rUpgrade)
    subInstallReq = "pip install -r bin/Sublist3r/requirements.txt"
    os.system(subInstallReq)
    log("Sublist3r Installed\n")
    eyeWitnessUpgrade = "git clone https://github.com/FortyNorthSecurity/EyeWitness.git ./bin/EyeWitness"
    log("\n\033[1;31mInstalling EyeWitness \033[1;37m" + eyeWitnessUpgrade)
    os.system(eyeWitnessUpgrade)
    eyeInstallReq = "bash bin/EyeWitness/setup/setup.sh"
    log("\n\033[1;31mRunning Command: \033[1;37m")
    os.system(eyeInstallReq)
    cpphantomjs = "cp phantomjs ./bin/EyeWitness/bin/"
    os.system(cpphantomjs)
    movephantomjs = "mv phantomjs bin/"
    os.system(movephantomjs)
    log("\nEyeWitness Installed\n")
    enumallUpgrade = "git clone https://github.com/jhaddix/domain.git ./bin/domain"
    log("\n\033[1;31mInstalling Enumall \033[1;37m")
    log("\nenumall Installed\n")
    os.system(enumallUpgrade)
    knockpyUpgrade = "git clone https://github.com/guelfoweb/knock.git ./bin/knockpy"
    log("\n\033[1;31mInstalling Knock \033[1;37m")
    os.system(knockpyUpgrade)
    log("\nKnockpy Installed\n")
    sublstUpgrade = "git clone https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056 ./bin/sublst"
    log("\n\033[1;31mCopying JHaddix All Domain List: \033[1;37m")
    log("\nJHaddix All Domain List Installed\n")
    os.system(sublstUpgrade)
    SLsublstUpgrade = "wget -O ./bin/sublst/sl-domains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt"
    log("\n\033[1;31mCopying SecList Domain List \033[1;37m")
    log("\nSecList Domain List Installed\n")
    os.system(SLsublstUpgrade)
    subbruteUpgrade = "git clone https://github.com/TheRook/subbrute.git ./bin/subbrute"
    log("\n\033[1;31mInstalling Subbrute \033[1;37m")
    os.system(subbruteUpgrade)
    log("\nSubbrute Installed\n")
    amassUpgrade = "go get -u github.com/OWASP/Amass/..."
    log("\n\033[1;31mInstalling Amass \033[1;37m")
    os.system(amassUpgrade)
    subfinderUpgrade = "go get -u github.com/subfinder/subfinder"
    log("\n\033[1;31mInstalling Subfinder \033[1;37m")
    os.system(subfinderUpgrade)
    massdnsUpgrade = "git clone --branch v0.2 --single-branch https://github.com/blechschmidt/massdns ./bin/massdns"
    log("\n\033[1;31mInstalling massdns \033[1;37m")
    os.system(massdnsUpgrade)
    massdnsMake = "make -C ./bin/massdns"
    os.system(massdnsMake)
    log("\nMassdns Installed\n")
    os.system("cp ./bin/subbrute/resolvers.txt ./")
    if "kali" in unameChk:
        reconNGInstall = "apt-get install recon-ng"
        log("\n\033[1;31mInstalling Recon-ng \033[1;37m")
        os.system(reconNGInstall)
        log("\nRecon-ng Installed\n")
    else:
        log("Please install Recon-ng - https://bitbucket.org/LaNMaSteR53/")
    log("\n\033[1;31mAll tools installed \033[1;37m")
    log("Changing back to old working directory: {}".format(old_wd))
    os.chdir(old_wd)


def writeFiles(name):
    """Writes info of all hosts from subhosts
    """
    subdomainCounter = 0
    fileExt = {
        "sublist3r": ".txt",
        "knock": ".csv.txt",
        "enumall": ".lst",
        # "massdns": ".txt",
        "amass": ".txt",
        "subfinder": ".txt",
        "altdns": ".txt"
    }
    fileName = output_base + "_" + name + fileExt[name]

    log("\n Opening %s File" % name)
    try:
        with open(fileName, "r") as f:
            SubHosts = f.read().splitlines()

        with open(subdomainAllFile, "a") as f:
            f.writelines("\n\n" + name)
            for hosts in SubHosts:
                hosts = "".join(hosts)
                f.writelines("\n" + hosts)
                subdomainCounter += 1
        os.remove(fileName)
        log("\n%s Subdomains discovered by %s" % (subdomainCounter, name))
    except:
        log("\nError Opening %s File!\n" % name)
    return subdomainCounter


def allinone():
    log("\nCombining Domains Lists\n")
    with open(subdomainAllFile, "r") as domainList:
        uniqueDomains = set(domainList)
        domainList.close()
        uniqueDomainsOut = open(subdomainUniqueFile, "w")
        for domains in uniqueDomains:
            domains = domains.replace("\n", "")
            if domains.endswith(domain):
                uniqueDomainsOut.writelines("https://{}\n".format(domains))
                if ports is not False:
                    uniqueDomainsOut.writelines("https://{}:8443\n".format(domains))
                if secure is False:
                    uniqueDomainsOut.writelines("http://{}\n".format(domains))
                    if ports is not False:
                        uniqueDomainsOut.writelines("http://{}:8080\n".format(domains))
    time.sleep(1)
    # rootdomainStrip = domain.replace(".", "_")
    # log("\nCleaning Up Old Files\n")
    # try:
    #     os.system("rm {}*".format(domain))
    #     os.system("rm {}*".format(rootdomainStrip))
    # except:
    #     log("\nError Removing Files!\n")


def subdomainfile():
    names = ["sublist3r", "knock",  "amass", "subfinder"]

    # "enumall",

    for name in names:
        writeFiles(name)
    allinone()





def vpncheck():
    vpnck = requests.get("https://ifconfig.co/json")
    # Change "City" to your city")
    if "City" in vpnck.text:
        log("\n\033[1;31mNot connected via VPN \033[1;37m")
        log("\n{}".format(vpnck.content))
        log("\n\033[1;31mQuitting domained... \033[1;37m")
        quit()
    else:
        print("\n\033[1;31mConnected via VPN \033[1;37m")
        print("\n{}".format(vpnck.content))
        time.sleep(5)


def options():
    if vpn:
        vpncheck()
    if install:
        upgradeFiles()
    elif upgrade:
        upgradeFiles()
    else:
        if domain:
            sublist3r()
            # enumall()
            subfinder()
            knockpy()
            amass()
            subdomainfile()
            if altdns:
                altdns(subdomainUniqueFile)
                allinone()
            checkresponse(subdomainUniqueFile)
            massdns()
            extractip()
            nmap()
            if not noeyewitness:
                eyewitness(responsivefile)
        else:
            print("\nPlease provide a domain. Ex. -d example.com")
    print("\n\033[1;34mAll your subdomain are belong to us\033[1;37m")


if __name__ == "__main__":
    banner()
    args = get_args()
    domain = args.domain
    altdns= args.altdns
    secure = args.secure
    bruteforce = args.bruteforce
    upgrade = args.upgrade
    install = args.install
    ports = args.ports
    vpn = args.vpn
    quick = args.quick
    bruteall = args.bruteall
    active = args.active
    noeyewitness = args.noeyewitness

    newpath = domain
    if not os.path.exists(newpath):
        os.makedirs(newpath)

    script_path = os.path.dirname(os.path.realpath(__file__))
    output_base = "{}/{}".format(domain,domain)
    nmapoutputfile = "{}_nmapportscanning.txt".format(output_base)
    responsivefile = "{}_responsive.txt".format(output_base)
    subdomainUniqueFile = "{}_unique.txt".format(output_base)
    subdomainAllFile = "{}_all.txt".format(output_base)
    logfile = open("{}_log.txt".format(output_base),"w")
    massdnsoutput = "{}_massdnsoutput.txt".format(output_base)
    iplist = "{}_iplist.txt".format(output_base)
    ipscanningfile = "{}_ipscanning.html".format(output_base)
    word_file = os.path.join(
        script_path, "bin/sublst/all.txt" if bruteall else "bin/sublst/sl-domains.txt"
    )

    options()
    logfile.close()
