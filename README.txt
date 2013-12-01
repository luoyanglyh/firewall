System specifications:
Ubuntu 12.10
Processor: Intel Core i5-3210M CPU
OS Type: 32 bit

Instructions:
Program is designed to execute in two ways.
1. pcap file as an input using offline mode
Specify argument 0 to run in this way. Commandds:
	$ make
	$./firewall 0 <dumpfile> <firewall_rules_file>
2. On interfaces 
Specify argument 1 to run in this way. 
Commands:
	$ make
	$ sudo ./firewall 1 <first eth interface on firewall> <IP of first eth interface> <MAC of first eth interface> <second eth interface on firewall> <IP of second eth interface> <MAC of second eth interface> <firewall_rules_file>
Example:
	$ sudo ./firewall 1 eth0 30.10.1.128 00:0c:29:7b:00:69 eth1 20.10.1.128 00:0c:29:7b:00:73 rules

Format of firewall rules file:
Firewall blocks all traffic by default. Rules file contains a rule per line. Format of that line is
<Source IP> <Destination IP> <Source Port> <Destination Port> <0/1>
For this milestone I have kept firewall rules very simple. 0 or 1 indicates the decision to block or allow.
Example:
20.10.1.130 30.10.1.129  756 67  0
means block traffic from 20.10.1.130:756 to 30.10.1.129:67

20.10.1.130 30.10.1.129  756 67  1
means allow traffic from 20.10.1.130:756 to 30.10.1.129:67

For ICMP protocol, as there are no ports, specify them as -1.

Approach:
The program uses libcap functions to look at the packets. Functions such as pcap_open_live, pcap_open_offline, pcap_inject, pcap_loop, pcap_dump are used.
1. Offline Mode:
In this mode user provides 2 files. One is pcap file and another is set of rules. The program uses pcap_dump to store the output of the firewall.
Note that in offline mode I am assuming there is no way to know the destination MAC using arping or some method. So I do not change MAC addresses in this method. It just checks if the source and destination IP and Ports match and according to allow/block policy it will either write into the file or simply ignore it.

2. Interfaces:
Setup:
In this method I used 3 virtual machines -> Source, Firewall and Destination. The names are for simplicity and this supports two-way communication.
Using Virtual Network Editor, I configured IP ranges for VMNet2 as 20.10.1.1 and VMNet3 as 30.10.1.1.
On Firewall I setup 2 network interfaces say VMNet2 -> eth1 and VMNet3 ->eth0. I noted down their IP and MAC addresses.
On Source I configured network interface as VMNet2. I configured its /etc/network/interfaces file to give it a static IP 20.10.1.130 and gateway as Firewall's interface configured on 20.10.1.133. 
On Destination I configured network interface as VMNet3. I configured its /etc/network/interfaces file to give it a static IP 30.10.1.130 and gateway as Firewall's interface configured on 30.10.1.133.
With this setup, Source and Firewall could talk to each other and so as Destination and Firewall. But Source and Desination commmunication was still not happening.

Passing packet:
For a packet to go the the destination, I needed MAC address of the destination. I executed arping command parsed the output and extracted the destination MAC address.

For a given packet I replaced its Source MAC with other interface's MAC and Destination MAC with the one which I got from arping.
The program shows before and after state of the packet consisting of source and destination MAC and IPs
After that I used pcap_inject command to inject packet from one interface to another inside the firewall.

Once this is done, the packet could easily flow though Source to Destination.

Multiprocesses?
As I needed two way communication, I forked the process. So Parent one was taking care of packets coming on eth0 injecting them on eth1. And the second one was taking care of packets coming on eth1 and injecting them on eth0.
The loop is completed now.

I used ping command to send packets. 

Firewall Rules?
For each packet I compared SourceIP, DestinationIP, SourcePort and DestinationPosrt with the firewall rules. If all of them macth AND if the allow/block bit is 1 then and then only I sent the packet to pacp_inject. The program will show "Packet allowed by firewall" for such cases. If all of them are matched and if the bit is 0 then it is not passes further. The program will show "Packet blocked by firewall".

Testing?
With above setup, I tested sending ping requests both ways. I used Wireshark a lot to track the packets.

Why so many arguments?
Basically to TRY to make it work it on any machine. I can explain this in the demo.