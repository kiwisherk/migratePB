#!/usr/bin/env python3
#    migratePB.py
#
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


import jxmlease
import json
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import *
from lxml import etree
import pprint
import argparse
import sys
import re
import ipaddress
from IPy import IP

SECURITY='<security></security>'

ST0unit = 0
ST0addr = ipaddress.ip_address('1.1.1.0')

LocalAddress = "172.16.13.3"
ExternalInterface = 'ge-0/0/2'

#
#----
#
# Each Route Based tunnel requires one st0 unit. We give it an IP address to facilitate debugging.
#
def PrintST0(ST0unit):
    global ST0addr
    print(f'set interfaces st0 unit {ST0unit} family inet address {ST0addr}/31')
    ST0addr += 2

#
#----
#
# Output the IKE Gateway. This assumes that there is an IKE Policy named 'IKE-POL'
#
def PrintIke(gwName, address):


#    print(f'set security ike policy IKE-POL mode main')
#    print(f'set security ike policy IKE-POL proposals standard')
#    print(f'set security ike policy IKE-POL pre-shared-key ascii-text "$9$jjik.PfQ3n9p08XN-wsfTQ"')

    print(f'set security ike gateway {gwName} ike-policy IKE-POL')
    print(f'set security ike gateway {gwName} address {address}')
    print(f'set security ike gateway {gwName} external-interface {ExternalInterface}')
    print(f'set security ike gateway {gwName} local-address {LocalAddress}')

#
#---
#
# Output the IPSec vpn commands. This assumes that there is an IPSec Policy named 'IPSec-POL'
#
def PrintIPsec(vpnName, gwName, ST0unit):

    print(f'set security ipsec proposal standard')
    print(f'set security ipsec policy IPSEC-POL proposals standard')
    print(f'set security ipsec vpn {vpnName} bind-interface st0.{ST0unit}')
    print(f'set security ipsec vpn {vpnName} ike gateway {gwName}')
    print(f'set security ipsec vpn {vpnName} ike ipsec-policy IPSEC-POL')
    print(f'set security ipsec vpn {vpnName} establish-tunnels immediately')

#
#----
#
# Print the required Security Policy. This is caled twice for each RB Tunnel, once with from/to and once with to/from.
# 
def PrintPolicy(tp):

    fromZone = tp['from-zone']
    toZone = tp['to-zone']
    policyName = tp['name']
    src = tp['src']
    dst = tp['dst']

    print(f'set security policies from-zone {fromZone} to-zone {toZone} policy {policyName} match source-address {src}')
    print(f'set security policies from-zone {fromZone} to-zone {toZone} policy {policyName} match destination-address {dst}')
    print(f'set security policies from-zone {fromZone} to-zone {toZone} policy {policyName} match application any')
    print(f'set security policies from-zone {fromZone} to-zone {toZone} policy {policyName} then permit')

#
#----
#
# Every time this function is called, we increment the unit number for the st0 interface.
#
def GenST0unit():
    global ST0unit
    ST0unit += 1
    return(ST0unit)

#
#----
#
# Read the command line for the arguments
#                                                                                                         
def ParseArgs():
    """Parse the command line arguments."""

    parser = argparse.ArgumentParser(description="Convert PB to TS IPSec")

    parser.add_argument('--user', '-u')    
    parser.add_argument('--password', '-w')
    parser.add_argument('--logfile', '-l')    
    parser.add_argument('--debug', '-d', action='store_true')
    parser.add_argument('--localaddress')    

    group = parser.add_mutually_exclusive_group(required=True)
    # The file is the output of 'show configuration | display xml'
    group.add_argument("--file", type=argparse.FileType('r'), help="Specifiy read config from an XML file")
    group.add_argument("--host", help="Specifiy read config from a host")    

    args = parser.parse_args()

    return(args)

#
#----
#
# Return the Gateway for a specific IPSec VPN.
#
def FindIPSecGW(ipsecVPN):
    ipp = xml['configuration']['security']['ipsec']['vpn']
    
    for vpn in ipp:
        if ipsecVPN == str(vpn['name']):
            name = str(vpn['name'])
            ike = vpn['ike']
            gateway = str(ike['gateway'])
            ret = {'name': name, 'gateway':gateway}            
            return(ret)

#
#------
#
# The AddressBooks in Junos contains both 'address' entries and 'address-set' entries. A policy can refer to either one. So, we parse the
# data structure and create two Lists of Dicts. The first one (AddressAddrBooks) has all the 'address' elements and the other (AddressSetBooks)
# all the 'address-set' elements. So, when we have an address value in a Security Policy, first we look it up in the AddressAddrBooks list.
# If we find a match, great! If not, then we look in AddressSetBooks. If we find a match there, then we use the value of the match to look in
# AddressAddrBooks.
#
def FindAddressBooks(xml):
    AddressAddrList = []
    AddressSetList = []    
    for abs in xml['configuration']['security']['address-book']:
        for key in abs:
            if key == 'address':

                AddressAddrList = []                
                if type(abs[key]) == jxmlease.dictnode.XMLDictNode:
                    print("Addr: Does this get called?")                    

#                    addrs = abs[key]                    
#                    name = str(addrs['name'])
#                    prefix = str(addrs['ip-prefix'])
#                    AddressList.append({name:prefix})

                elif type(abs[key]) == jxmlease.listnode.XMLListNode:
#                    print("Hey, I am here!")
                    addrs = abs[key]
                    index = 0

                    while index < len(addrs):
                        for key in addrs[index]:
                            prefix = []
                            if key == 'name':
                                name = str(addrs[index][key])
                            elif key == 'ip-prefix': 
                                prefix.append(str(addrs[index][key]))
                                AddressAddrList.append({name:prefix})
                        index += 1

            if key == 'address-set':
                if type(abs[key]) == jxmlease.dictnode.XMLDictNode:
#                    print("Set: Does this get called?")                                        
                    asName = str(abs[key]['name'])
                    ASaddrList = []

                    for n in abs[key]['address']:
                        if len(abs[key]['address']) == 1:
                            addrName = abs[key]['address']['name']
                        else:
                            addrName = n['name']
                        ASaddrList.append(str(addrName))                        

                    AddressSetList.append({asName:ASaddrList})

                elif type(abs[key]) == jxmlease.listnode.XMLListNode:
#                    print("2 Hey, I am here!")
                    for i in abs[key]:
                        asName = str(i['name'])
                        ASaddrList = []
                        for n in i['address']:
                            addrName = n['name']
                            ASaddrList.append(str(addrName))                            
                        AddressSetList.append({asName:ASaddrList})
                        
        AddressAddrBooks.append({str(abs['name']):AddressAddrList})
        AddressSetBooks.append({str(abs['name']):AddressSetList})

    if (Debug):
        print('AddressAddrBooks...')
        pprint.pprint(AddressAddrBooks)
        print('AddressSetBooks...')    
        pprint.pprint(AddressSetBooks)
        
    return(AddressAddrBooks, AddressSetBooks)
#
#-----
#
# Policies = [{from-zone: FROM, to-zone: TO, policies: {Name: VPN-IN-TS,
# Matches: {'source-address': 'Docker3b-Net', 'destination-address': 'Docker4b-Net', 'application': 'any'},
# Then: {'permit': {'tunnel': {'ipsec-vpn': 'VPN-to-Docker3a'}}}"]
#
# We make a list of all the defined policies so we can recreate them for the RB tunnels. The key 'policy' is
# used twice in the Security Policy definition. Once for the whole policy, including the from/to zones and also
# within the policy where we match the src/dst/app. This function finds the first polic type and calls 'FindSubPolicies'
# to find the second.
#
def FindPolicies(xml):

    for pols in xml['configuration']['security']['policies']['policy']:
        FromZone=''
        ToZone=''
        for pol in pols:
            SubPolicies = []
            if (pol == 'from-zone-name'):
                FromZone = str(pols[pol])
            elif (pol == 'to-zone-name'):
                ToZone = str(pols[pol])                
            elif (pol == 'policy'):

                if type(pols[pol]) == jxmlease.dictnode.XMLDictNode:                    
                    SubPolicies = FindSubPolicies(pols[pol], SubPolicies)
                else:
                    index = 0                    
                    while index < len(pols[pol]):
                        SubPolicies = FindSubPolicies(pols[pol][index], SubPolicies)
                        index += 1
            else:
                print('Error: Can not parse policies!')
                exit()
        Policies.append({'from-zone': FromZone, 'to-zone': ToZone, 'policies': SubPolicies})

    return(Policies)
#
#----
#
# Find the part of the policy used for src/dst/app selection.
#
def FindSubPolicies(Policy, SubPolicies):

    Matches = {}
    Then = {}

    for k2 in Policy:
        if k2 == 'name':
            Name =  Policy[k2]

        elif k2 == "match":                            
            for k in Policy[k2]:
                Matches[k] =str(Policy[k2][k])

        elif k2 == "then":
            Then = (Policy[k2])

    SubPolicies.append({'name': str(Name), 'matches': Matches, 'then': Then })
    return(SubPolicies)

#
#----
#
# In FindTunnelPolicies, we look at each policy in the Policies list and if the policy permit line includes
# '... then permit tunnel VPN' then we include it in the list of Tunnel Policies that we return.
#
def FindTunnelPolicies(Policies):
#    print("In FindTunnelPolicies")
    TunnelVPNs = []
    for index in range(len(Policies)):
        fromZone = Policies[index]['from-zone']
        toZone = Policies[index]['to-zone']        

        for key in Policies[index]:
            FoundTunnel = False
            name=''
            dst=''
            src=''
            if key == 'policies':
                for p in Policies[index][key]:
                    name = p['name']

                    if 'permit' in p['then'] and p['then']['permit']:
                        tunnel = p['then']['permit']

                        if 'tunnel' in tunnel and tunnel['tunnel']:
                            
                            ipsecVpn = tunnel['tunnel']
                            VPNname = str(ipsecVpn['ipsec-vpn'])
                            FoundTunnel = True

                    if 'application' in p['matches']:

                        for key in p['matches']:
                            if key == 'application':
                                pass
                            elif key == 'destination-address':
                                dst = p['matches'][key]
                            elif key == 'source-address':
                                src = p['matches'][key]
                            else:
                                print('Whats up?')
                            
                    if FoundTunnel:
                        msg = (f"Appending: from-zone': {fromZone}, 'to-zone': {toZone}, 'name': {name},"
                               f"'VPNname': {VPNname}, 'src': {src}, 'dst': {dst}" )

                        TunnelVPNs.append({'from-zone': fromZone, 'to-zone': toZone, 'name': name, 'VPNname': VPNname,
                                       'src': src, 'dst': dst })
                        FoundTunnel = False
    return(TunnelVPNs)

#
#----
#
# Here we make a list of IKE Gateways. Note that we cast each field with str(). This changes them from type jxmlease.dictnode.XMLDictNode
# and makes them easier to handle. Return a list of all the IKE Gateways.
#
def ParseIKE(xml):
    IkeGWs = []
    for ike in xml['configuration']['security']['ike']['gateway']:
        if (Debug):
            print(f"IKE GW: {ike['name']}")
        name = str(ike['name'])
        ikePolicy = str(ike['ike-policy'])
        address =  str(ike['address'])
        external = str(ike['external-interface'])
        locAddr = str(ike['local-address'])
        IkeGWs.append({'name': name, 'ike-policy': ikePolicy, 'address': address, 'external-interface': external, 'local-address': locAddr})
    return(IkeGWs)
        
    
#
#---
#
# Find each IKE Gatewal listed under 'security ipsec vpn...'
#
def FindGWs(xml):
    VPN = []
    for vpn in xml['configuration']['security']['ipsec']['vpn']:
        name = str(vpn['name'])
        gateway = str(vpn['ike']['gateway'])
        if Debug:
            print(f"GW name: {name} gw: {gateway}")
        VPN.append({'name': name, 'gateway': gateway})
    return(VPN)
#
#---
#
# Read through the zones and create a list of them with the interfaces in the zone.
#
def ParseZones(xml):
    Zones = []
    for zone in  xml['configuration']['security']['zones']['security-zone']:
        name = zone['name']
        interfaces = zone['interfaces']
        Zones.append({'name': str(name), 'interfaces': interfaces})
    if Debug:
        print(f"Zones: {Zones}")
    return(Zones)        
#
#-----
#
def FindAddrAddress(addr):
#    print(f"\n*** FindAddrAddress: Looking for {addr}")
    for AB in AddressAddrBooks:
#        print(f"AB: {AB}")
        ab = list(AB.keys())[0]
#        print(f"ab: {ab}")
        v = list(AB.values())[0]

        for i in v:
            name = list(i.keys())[0]
            addrs = list(i.values())[0]
#            print(f"name: {name}")
#            print(f"addrs: {addrs}")

            if (addr == name):
#                print(f"*** Found name: {name} addr: {addrs}")
                return(ab, addrs)
            if (addr == 'any'):
                return(ab, 'any')
#    print(f'Not found!\t{addr}')
    return(False, False)
#
#----
#
def FindSetAddress(addr):
#    print(f"\n*** YYY FindSetAddress: Looking for {addr}")
    for ASB in AddressSetBooks:
#        print(f"YYY ASB: {ASB}")
        asb = list(ASB.keys())[0]
#        print(f"YYY asb: {asb}")
        v = list(ASB.values())[0]

        for i in v:
            name = list(i.keys())[0]
            addrs = list(i.values())[0]
#            print(f"name: {name}")
#            print(f"addrs: {addrs}")

            if (addr == name):
#                print(f"*** Found name: {name} addr: {addrs}")
                return(name, addrs)
            if (addr == 'any'):
                return(name, 'any')
#    print(f'Not found!\t{addr}')
    return(False, False)
            
            
#
#-----
#
def ResolveAddresses(VPNs):
#    print(f"Len of VPNs {len(VPNs)}")

    for i in VPNs:
#        print(f"VPN: {i}")
#        print(f"Src: {i['src']}")
        src = FindAddrAddress(i['src'])
        i['src'] = src
#        print(f"Dst: {i['dst']}")
        dst = FindAddrAddress(i['dst'])
        i['dst'] = dst
#        print(f"Fixed VPN: {i}")

#
#---
#
def PrintABE(zone, ABE):
#    print(f"XXX*** Calling FindAddrAddress with {ABE}")
    book, addr = FindAddrAddress(ABE)
#    print(f' YYY*** PrintABE: book: {book} addr: {addr}\tzone: {zone}')
    if book == False:
#        print('YYY Address set')
        book, addr = FindSetAddress(ABE)
#        print(f"YYY FSA book: {book}\taddr: {addr}")
        
        for a in addr:
#            print(f"YYY Book: {book}\ta: {a}")

            print(f"set security address-book {book} address-set {ABE} {a}")
            book, ad = FindAddrAddress(a)
            for d in ad:
                print(f"set security address-book {book} address {a} {d}")
                print(f"set routing-options static route {d} next-hop st0.{ST0unit}")
            
    else:
#        print('ABE Address')
        print(f"set security address-book {book} address {ABE} {addr[0]}")

#
#---
#
def SetUp(*arg):
# Called with zero arguments
    global LocalAddress, Debug
    args = ParseArgs()
    Debug = args.debug

    if args.localaddress:
        try:
            IP(args.localaddress)
        except:
            print(f"Invalid LocalAddress: {args.localaddress}")
            exit()        
    LocalAddress = args.localaddress

        
    if args.host is not None:
        print(f'Host is: {args.host}')
        try:
            with Device(host=args.host, user=args.user, password=args.password) as dev:
#            with Device(host=args.host) as dev:                
                config = dev.rpc.get_config(filter_xml=SECURITY,
                            options={'inherit': 'inherit', 'database': 'committed', 'format': 'XML'})
                xml_data =etree.tostring(config, encoding='unicode', pretty_print=True)

                xml = jxmlease.parse(xml_data)
        except:
            print(f"Can't connect to: {args.host}")
            exit()
        
    elif args.file is not None:
        with args.file as xml_file:
            xml_data = xml_file.read()
            print('File')
            i =  jxmlease.parse(xml_data)
            xml = i['rpc-reply']
    else:
        print("We should not be here!")
        exit()
    return(xml)
#
#----
#
# Perhaps this is a poorly named function. It is called once per 'vpn' and it finds the name of the Gateway,
# the external-interface, the 'address' of the IPSec peer and the zone that the external-interface lives in.
# Also, in the 'security ipsec gateway external-interface NNN' a unit is not required, but is required in the
# 'security zones security-zones...' definition. Go figure...
#
#         gwName, exIntf, address, Zone = FindZone(Zones, GW, IkeGWs, ST0unit)
#
def FindZone(Zones, GW, IkeGWs, ST0unit):
    for i in IkeGWs:
        if i['name'] == GW['gateway']:
            gwName = i['name']
            exIntf = i['external-interface']
            address = i['address']

            for z in Zones:
                if (type(z['interfaces'])) == jxmlease.dictnode.XMLDictNode:
                    exName = z['interfaces']['name']
                    if re.match(r"ge-0/0/\d+\.\d", exIntf):
                        print(f"Found a match! {exIntf}")
                    else:
                        exIntf = exIntf + ".0"

                    if z['interfaces']['name'] == exIntf:
                        Zone = z['name']
#                        if Debug:
#                            print(f"Zone: {z['name']} Interfaces: {z['interfaces']}")
#                            print(f"\t exIntf {exIntf}\t address: {address}")            

                        print(f"set security zone security-zone {Zone} interface st0.{ST0unit}")
    return(gwName, exIntf, address, Zone)
#
#------
#
def main():
    global xml 
    global AddressAddrBooks, AddressSetBooks, Policies, VPN
    AddressAddrBooks = []
    AddressSetBooks = []    
    Policies = []

    xml = SetUp()

# These functions read the config, either from the actual router/firewall or from the xml output of 'show configuration | display xml'.
# They marshal the data in a series of data structures, mostly lists of dicts.

    AddressAddrBooks, AddressSetBooks = FindAddressBooks(xml)
    Zones = ParseZones(xml)
    GWs = FindGWs(xml)
    Policies = FindPolicies(xml)
    VPNs = FindTunnelPolicies(Policies)
    IkeGWs = ParseIKE(xml)    

# Now we take what we have learned and produce the config for each 'route-based' VPN.

    for tp in GWs:
        vpn = tp['name']
        print(f"\n#### vpn: {vpn}")

        GW = FindIPSecGW(vpn)
        vpnName = GW['name']
        ST0unit = GenST0unit()
        gwName, exIntf, address, Zone = FindZone(Zones, GW, IkeGWs, ST0unit)

        PrintIke(gwName, address)
        PrintIPsec(vpnName, gwName, ST0unit)
        PrintST0(ST0unit)
        for v in VPNs:
            if v['name'] == vpn:
                PrintPolicy(v)
                # We only print the 'from-zone' because we assume that there is a matching security policy
                # that goes the other way.
                PrintABE(v['from-zone'], v['src'])
                
#
#---
#
if __name__ == "__main__":
    main()
