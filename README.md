# MoniterBruteForceAttackForMail
<h3><img  src="https://img.shields.io/github/license/EKOISMYLOVE/MoniterBruteForceAttackForMail"/></h3>
For postfix and dovecot on Debian


Introduction
-------
This program design to detects the brute force attack of Mail.

Basically, it is detected through Scapy. When the conditions are met, Use iptables for post-processing protection.

Only for the mail service provided by postfix and dovecot.

Other related packages are not tested.
But modified through syslog and regular expressions. it should work.

Environment:
-------
Python Version : 2.7.13  
Postfix needs to enable the authentication function (the default is disable).  
The scapy library needs to be downloaded and installed.

How to Use:
-------------
1. Clone.
2. Create a passlist.txt in the same directory as passlist.txt.
3. Enter the whitelisted IP into the file.
4. Notice attention to permissions and paths
5. Set manual execution or execution at startup, but remember,  it should be tested first.
