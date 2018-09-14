# SDN Firewall
Pyretic is a Python platform that allows modular SDN (software-defined network) programming to manage packet-forwarding policies and monitor a network. This project uses Pyretic to create an externally configurable blacklist firewall using OpenFlow-enabled switches, where the policies reside in a configuration file.

`firewall_policy.py` contains the firewall implementation, and it parses a given configuration file to form the specified firewall rules. The form of a parased configuration file should look like:

rulenum, source MAC, destination MAC, source IP, destination IP, source port, destination port, protocol

`firewall.py` then parses the output from `firewall_policy.py` into a list of dictionaries and creates the appropriate match/pyretic actions. `firewall-config.pol` is the configuration file that will be used in this firewall simulation, which lists the following rules:

* Prohibit all systems from accessing a PPTP server running on server2.
* Prohibit all devices from connecting to a SSH on hosts e1, e2, and e3.
* Protect DNS and NTP services on server1 and server2 from all hosts. DNS and NTP servers on server3 should still remain accessible.
* Prevent hosts w1 and w2 from pinging mobile1 through ICMP.
* Prohibit all traffic destined to TCP ports 9950-9952 on host e3 from host e1.
* Restrict host mobile1 from communicating to hosts e1, e2, and e3 through TCP and UDP.

## Environment/Packages
* Ubuntu 14.04 LTS
* [Pyretic](https://github.com/frenetic-lang/pyretic)
* mininet (for network simulations)
* Wireshark (to analyze network traffic)
