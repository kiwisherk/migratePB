# migratePB
Migrate Juniper policy based VPNs to route based VPNs

# This script migrates the Junos config for Policy Based IPSec tunnels to Route Based IPSec tunnels. It connects to the Junos device hosting the PB tunnels
# (or it can use a file) and slurps in the config. Then it:
#     1) Parses the AddressBooks
#     2) Parses the Zones
#     3) Parses the IPSec config
#     4) Parses the Security Policies and finds all policy that have the 'then permit tunnel...' config in them. For each of these, a route based tunnel will be
#        created.
#     5) Parses the IKE config and finds all the Gateways
#
# After Parsing all the relavent configurations, it keys off IPSec tunnels to generate the Route Based config

# Caveats...
#     We assume that the config we are given is complete and correct and commits.
#     We assume that the security zones from the original device are in the new device.
#     We assume that the AddressBooks are present and attached to a zone. We could build a global address-book?
#     We assume that the Ike and IPSec policies are already defined in the new Junos Device. This includes the 
#         the 'pre-shared-key' from the original config. We could add some code to be able to change it.
#     We assume that there are only 'policy-based' VPNs in the original device. No idea what would happen if it also contained 'route-based' VPNs
#     We assume that 'routing-instances' are not used.
#     We assume that we will use /31 for the st0 interfaces. We also keep a counter for the unit numbers.
#     We assume that policies are always in recprocal pairs.


(venv) sherk@MBP:[~/unixdir/src/python/Junos] ./migratePB.py --help
usage: migratePB.py [-h] [--user USER] [--password PASSWORD] [--logfile LOGFILE] [--debug] [--localaddress LOCALADDRESS] (--file FILE | --host HOST)

Convert PB to TS IPSec

options:
  -h, --help            show this help message and exit
  --user USER, -u USER
  --password PASSWORD, -w PASSWORD
  --logfile LOGFILE, -l LOGFILE
  --debug, -d
  --localaddress LOCALADDRESS
  --file FILE           Specifiy read config from an XML file
  --host HOST           Specifiy read config from a host

