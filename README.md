# wifilocator
Locate wifi device or access point based on received signal strength  
Works off of radiotap headers added by the antenna's drivers  
The antenna must support monitor mode  
Must have the dbm Antenna Signal flag set in the radiotap header  
Even with the channel flag set, some drivers will still channel hop automatically  

<br>

```
wifilocator --help

A tool for locating the source of a wireless signal
or for listing detected transmitting addresses

Usage: wifilocator [ OPTIONS... ]

Options:
-l, --list			              	List detected transmitting addresses
-i, --interface <interface>	  		Specifies the interface to use
-m, --monitor			            Put the interface into monitor mode
-t, --target <mac address>	  		The MAC address to listen for
-c, --channel <channel>		    	Specifies channel to use
                                	Value < 1000 denotes channel, value > 1000 denotes MHz
-v, --verbose                       Output verbose information
-h, --help			              	Display this help message

Output Options:
--bssid-only			          	Only scan for access points
--maximum-addresses <num>	  		The maximum number of addresses to be
				                    listed by the --list option, default 32
--no-frame-counter		      		Do not output frame counters
--no-bar-in-place		        	Output dBm bar on consecutive lines
--no-aging			            	Do not age out addresses
--no-channel			          	Do not display channel

Notes:
The interface must be in monitor mode to operate
If --list and --target are used together --target will be ignored
The MAC address should be six groups of seperated hex digits, any case

Examples:
wifilocator -i wlan0 -m -l
wifilocator -i wlan0 -t xx:xx:xx:xx:xx:xx
wifilocator --interface wlan0 --list --no-frame-counter
```

<br>

Example output from <code>sudo wifilocator -i wlan0 -lm -c 52</code>  
![List Example](/img/wllist.png)

<br>

Example output from either using ```Enter``` when listing or ```sudo wifilocator -i wlan0 -t 74:97:79:FF:1D``` to target a specific address  
![Scan Example](/img/wltarg.png)

<br>

Checklist
- Take command line arguments
  - MAC to look for
  - Enable monitor mode
  - etc
- Create and bind raw socket
- Parse radiotap header flags
- Parse addr
- Display signal strength bar
- Add an active scan mode
- Add some sort of name resolution
- Rewrite parseaddr function
- Add BSSID only scan
- Do things in the alternate terminal
- Add signal handler for SIGINT
- Add channel hopping
- Add age out
- Filter by rx address
- Errors should be written to the normal buffer
- Add verbosity argument
- Add scanning for active channels
