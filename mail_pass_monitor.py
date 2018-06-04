# This script for postfix(SMTP) and Dovecot(POP3 IMAP)
# Set "disable_plaintext_auth = no" in dovecot to Test.
# You should create 'passlist.txt' and type in your whitelist IP address in same directory , Thanks.
# Suggest : Type Server's IP in passlist.txt.
# if you have many IP , Please change line and typing.
# passlist.txt Format :  
# 127.0.0.1
# 192.168.0.1

import threading
import os
import time
import socket
from scapy.all import *

# ---Global variable ---
failtimes = 3
recordIP = []
recordUser = []
recordBlockIP = []
lock = threading.Lock()
# --- Ban Time , it should bigger than checkTime , second---
blockTime = 600
# --- Check iptables Interval Time , second---
checkTime = 30
# --- Syslog path ---
syslogLogPath = "/var/log/syslog"

# --- Compare IP in list ---
def check_IP_Pass(ipAddress): 
    loadingFile = open('passlist.txt','r')
    passlist = loadingFile.read().splitlines()
    # --- Return True , False . and close file ---
    if ipAddress in passlist:
        loadingFile.close()
        return True
    else:
        loadingFile.close()
        return False

# --- Thread Target . ---
def start_sniff():
    print "[*] Start sniffing."
    sniff(filter="tcp port 110 or tcp port 25 or tcp port 143",prn=packet_callback,store=0)
    print "[*] Stop sniffing."

# --- packet callback ---
def packet_callback(packet):

    global recordIP
    global recordBlockIP

    if packet[TCP].payload:               
        mail_packet = str(packet[TCP].payload)

# --- For POP3 ---
        if "+ok logged in." in mail_packet.lower():
            clean_buffer(packet[IP].dst,packet[TCP].sport)  

        elif "-err [auth] authentication failed." in mail_packet.lower():
            check = check_IP_Pass(packet[IP].dst)
            if check == False:
               print "[*] Try POP3 Signing From : %s" % packet[IP].dst
               print "Block : %s " % recordBlockIP
               append_IP(packet[IP].dst,packet[TCP].sport)

# --- For IMAP ---
        elif "a ok" in mail_packet.lower():
            clean_buffer(packet[IP].dst,packet[TCP].sport)
            
        elif "a no" in mail_packet.lower() and "authentication failed." in mail_packet.lower():
            check = check_IP_Pass(packet[IP].dst)
            if check == False:
                print "[*] Try IMAP Signing From : %s" % packet[IP].dst
                append_IP(packet[IP].dst,packet[TCP].sport)

# --- For SMTP ---
        elif "235 Authentication succeeded" in mail_packet.lower():
            clean_buffer(packet[IP].dst,packet[TCP].sport)
        
        elif "535 5.7.8 error: authentication failed: vxnlcm5hbwu6" in mail_packet.lower():
            check = check_IP_Pass(packet[IP].dst)
            if check == False:
                print "[*] Try SMTP Signing From : %s" % packet[IP].dst
                append_IP(packet[IP].dst,packet[TCP].sport)

# --- Drop client packet ---
def deny_client(ipAddress,port):
    # --- set start time ---
    i = str(time.ctime())
    i = str(i.split()[3])
    i = i[:-3]
    port = str(port)

    # --- iptables rule --- 
    j = subprocess.check_output('iptables -A INPUT -i ens33 -s '+ ipAddress + ' -p tcp --dport '+ port + ' -j DROP -m comment --comment \"ScriptBan ' + str(i) + '\"', shell=True)

    return 0

# --- accept banned client ---
def accept_client():
    global blockTime
    global checkTime
    global recordBlockIP
    global lock

    while True:
        # --- Get now time ---
        i = str(time.ctime())
        i = i.split()[3]
        i = i[:-3]
        # --- Get start time in iptables rules ---
        k = subprocess.check_output("iptables -L -n | grep ScriptBan | awk \'{print $10}\' " ,shell=True)
        l = k.splitlines()

        for ll in l:
            Time = time_calc(ll,i)
            if Time > blockTime:
                # Cause sometimes 2 thread accepts same variable(recordBlockIP) in same time.
                lock.acquire()
                try:
                    # --- Delete IP in recordBlockIP list 
                    ip = subprocess.check_output("iptables -L -n --line-number | grep " + str(ll) + "| awk \'{print $5} \'",shell=True)
                    port = subprocess.check_output("iptables -L -n --line-number | grep " + str(ll) + "| awk \'{print $8} \'",shell=True)
                    port = port.split(':')[1].replace('\r','').replace('\n','').replace(' ','')
                    ip = ip.replace('\r','').replace('\n','').replace(' ','')
                    ip = str(ip) +':'+ str(port)
                    print ip
                    recordBlockIP = [x for x in recordBlockIP if x != ip]
                except:
                    print recordBlockIP
                lock.release()
                # --- Delete rule with line number --- 
                m = subprocess.check_output("iptables -L -n --line-number | grep " + str(ll) + "| awk \'{print $1}\'" ,shell=True)
                os.system('iptables -D INPUT %s' %  m)
        time.sleep(checkTime)

# --- echo imformation and write in syslog ---
def syslog_imformation(ipAddress,port):
    i = str(time.ctime())
    i = i.split()
    # --- Set log Format ---
    if int(i[2]) < 10:
        i = str(i[1]) + "   " + str(i[2]) + " " + str(i[3])
    elif int(i[2]) >= 10:
        i = str(i[1]) + " " + str(i[2]) + " " + str(i[3])
    j = socket.gethostname()
    # --- Determine service for write in different log ---
    if port is 110 or port is 143:
        i = i + " " + j + " dovecot/sniff[0001] : Ban IP %s ." % ipAddress
        print i
        os.system('echo ' + i + ' >> ' + syslogLogPath)
    elif port is 25:
        i = i + " " + j + " postfix/sniff[0001] : Ban IP %s ." % ipAddress
        os.system('echo ' + i + ' >> ' + syslogLogPath)
    return 0

# --- record failed times and next step . ---
def append_IP(ipAddress,port):
    global recordIP
    global recordBlockIP
    global lock
    global failtimes
    client = str(ipAddress) + ":" + str(port)
    # --- Compare client ip  with whitelist ---
    if client not in recordBlockIP:
        recordIP.append(client)
        print recordIP
        # --- client fails > failtimes . ---
        if recordIP.count(client) >= failtimes:
            # --- Cause accept_client() ---
            lock.acquire()
            recordBlockIP.append(client)
            lock.release()
            deny_client(ipAddress,port)
            syslog_imformation(ipAddress,port)
            # --- Clear fail history ---
            recordIP = [x for x in recordIP if x != client]
        return 0
    else:
        return 0

def clean_buffer(ipAddress,port):
    global recordIP
    client = str(ipAddress) + ":" + str(port)
    recordIP = [x for x in recordIP if x != client]
    return 0

def append_user(userName,ipAddress):
    global recordUser
    recordUser.append(userName +":"+ ipAddress)
    print recordUser

def deleteEnd(string):
    s = string[:-2]
    return s

def time_calc(recordTime,nowTime):
    if int(nowTime.split(':')[0]) is 0 and int(recordTime(':')[0]) is 23:
        nowTime = (int(nowTime.split(':')[0])+24)*3600 + int(nowTime.split(':')[1])*60
        recordTime = int(recordTime.split(':')[0])*3600 + int(recordTime.split(':')[1])*60
    else:
        nowTime = int(nowTime.split(':')[0])*3600 + int(nowTime.split(':')[1])*60
        recordTime = int(recordTime.split(':')[0])*3600 + int(recordTime.split(':')[1])*60
    timeDifference = nowTime - recordTime
    return timeDifference

# --- Create threads pool and append function. ---
threads = []
threads.append(threading.Thread(target=accept_client))
threads.append(threading.Thread(target=start_sniff))

# --- Set daemon True because ---
# --- When main thread error or cancel , daemon thread will end , not running . zzz ---
for i in threads:
    i.daemon = True
    i.start()

# --- if all son thread ending , this script will end. ---
while threading.activeCount() > 0:
    time.sleep(1)
