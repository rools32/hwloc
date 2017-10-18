#!/usr/bin/env python2
import re
from xml.dom import minidom
dom = minidom.parse('topology.xml') # opareport -o topology

HOST=0
SWITCH=1

domNodes = dom.getElementsByTagName("Nodes")[0]
nodes = {}
partitions = set()

# Hosts (FIs)
fis = domNodes.getElementsByTagName("FIs")[0]
numHosts = int(fis.getElementsByTagName("ConnectedFICount")[0].firstChild.nodeValue)
print("Number of hosts: %d" % numHosts)
for host in fis.getElementsByTagName("Node"):
    guid = host.getElementsByTagName("NodeGUID")[0].firstChild.nodeValue
    description = host.getElementsByTagName("NodeDesc")[0].firstChild.nodeValue
    name = description.split()[0]
    try:
        partition = re.search('^([a-zA-Z-]+).*$', name).group(1)
        partitions.add(partition)
    except AttributeError:
        pass

    nodes[guid] = {'id': guid, 'description': description, 'name': name,
            'capacity': 1, 'type': HOST}
if len(nodes) != numHosts:
    print("Oups: %d hosts found (out of %d)" % (len(nodes), numHosts))

# Switches
switches = domNodes.getElementsByTagName("Switches")[0]
numSwitches = int(switches.getElementsByTagName(
    "ConnectedSwitchCount")[0].firstChild.nodeValue)
print("Number of switches: %d" % numSwitches)
for switch in switches.getElementsByTagName("Node"):
    nodeType = 1
    guid = switch.getElementsByTagName("NodeGUID")[0].firstChild.nodeValue
    description = switch.getElementsByTagName(
            "NodeDesc")[0].firstChild.nodeValue
    numPorts = len(switch.getElementsByTagName("Port"))
    nodes[guid] = {'id': guid, 'description': description, 'name': '',
            'capacity': numPorts, 'type': SWITCH}
if len(nodes) != numSwitches+numHosts:
    print("Oups: %d switches found (out of %d)" %
            (len(switches)-numHosts, numSwitches))
numNodes = len(nodes)

# Links
links = {}
linkSummary = dom.getElementsByTagName("LinkSummary")[0]
numLinks = int(linkSummary.getElementsByTagName(
    "LinkCount")[0].firstChild.nodeValue)
print("Number of links: %d" % numLinks)
linkID = 0
for l in linkSummary.getElementsByTagName("Link"):
    link = []
    ports = l.getElementsByTagName("Port")
    for port in ports:
        guid = port.getElementsByTagName("NodeGUID")[0].firstChild.nodeValue
        nodeType = port.getElementsByTagName("NodeType")[0].firstChild.nodeValue
        if not guid in nodes:
            print("Oups: node %s not found but in link" % guid)
        portNum = port.getElementsByTagName("PortNum")[0].firstChild.nodeValue
        link.append({'id': guid, 'port': portNum})
    # save the link in both ways
    for first in (0, 1):
        src = link[first]['id']
        dst = link[1-first]['id']
        if src not in links:
            links[src] = {}
        if dst not in links[src]:
            links[src][dst] = []
        currLink = {'hosts': (link[first], link[1-first]), 'id': 2*linkID+first,
                'otherid': 2*linkID+1-first}
        linkID += 1
        links[src][dst].append(currLink)

################################################################################
# Write file
with open('netloc/omnipath-nodes.txt','w') as f:
    # Version
    f.write("1\n") # Version
    f.write("omnipath\n") # Subnet
    f.write("\n") # Path to hwloc
    f.write("%d\n" % numNodes) # Number of nodes

    # Nodes
    for node in nodes.values():
        # phyID,logID,type,partition,description,hostname
        line = "%s,%s,%d,%d,%s,%s" % (node['id'], node['id'], node['type'], 0,
                node['description'], node['name'])
        f.write(line+"\n")

    # Nodes
    for src, dstLink in links.iteritems():
        line = "%s" % src
        for dst, link in links[src].iteritems():
            numRepeats = len(link)
            speed = 100*numRepeats
            # src,dest,speed,partitions,numLinks,
            line += ",%s,%d,%d,%d" % (dst, speed, 0, numRepeats)
            for l in link:
                # id,port1,port2,width,speed,gbits,desc,other_way_id,partitions
                line += ",%d,%s,%s,%s,%s,%s,%s,%d,%d" % \
                        (l['id'], l['hosts'][0]['port'], l['hosts'][1]['port'],
                                '', '', 100, '', l['otherid'], 0)
        f.write(line+"\n")
    # Partitions
    f.write(','.join(partitions)+"\n")

