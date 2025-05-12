# wifilocator
Locate wifi device or access point based on received signal strength

Works off of radiotap headers added by the interface drivers

Must have the dbm Antenna Signal flag set

Checklist
- Take command line arguments
  - MAC to look for
  - Enable mooitor mode
  - etc
- Create and bind raw socket
- Parse radiotap header flags
- Parse addr
- Display signal strength bar
