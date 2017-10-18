#!/usr/bin/env python2
import re
from xml.dom import minidom
dom = minidom.parse('snapshot.xml') # opareport -s -r -o snapshot"

def fmtID(i):
    return re.sub(r'^0x(.{4})(.{4})(.{4})(.{4})', r'\1:\2:\3:\4', i)

HOST=0
SWITCH=1

domNodes = dom.getElementsByTagName("Nodes")[0]
nodes = {}
linksByID = {}
partitions = set()
subnets = set()

# Nodes
for node in domNodes.getElementsByTagName("Node"):
    guid = fmtID(node.getElementsByTagName("NodeGUID")[0].firstChild.nodeValue)
    description = node.getElementsByTagName("NodeDesc")[0].firstChild.nodeValue
    nodeTypeRaw = int(node.getElementsByTagName(
        "NodeType_Int")[0].firstChild.nodeValue)
    if nodeTypeRaw == 1:
        nodeType = HOST
    else:
        nodeType = SWITCH

    if nodeType == HOST:
        name = description.split()[0]
        try:
            partition = re.search('^([a-zA-Z-]+).*$', name).group(1)
            partitions.add(partition)
        except AttributeError:
            pass
    else:
        name = ''
        partition = ''

    ports = node.getElementsByTagName("PortInfo")
    numPorts = len(ports)
    for port in ports:
        portID = port.attributes["id"].nodeValue
        subnet = fmtID(port.getElementsByTagName("SubnetPrefix")[0]\
                .firstChild.nodeValue)
        if not subnet in nodes:
            nodes[subnet] = {}
        width = port.getElementsByTagName("LinkWidthActive_Int")[0]\
                .firstChild.nodeValue
        speed = port.getElementsByTagName("LinkSpeedEnabled_Int")[0]\
                .firstChild.nodeValue
        linksByID[portID] = {'subnet': subnet, 'width': width, 'speed': speed}

        if not guid in nodes[subnet]:
            nodes[subnet][guid] = {'id': guid, 'description': description,
                    'name': name, 'capacity': numPorts, 'type': nodeType,
                    'partition': [partition]}

for s,v in nodes.items():
    print("subnet %s, len %d" % (s, len(v)))


# Links
links = {}
allLinks = dom.getElementsByTagName("Links")[0]
linkID = 0
for l in allLinks.getElementsByTagName("Link"):
    link = []
    src = l.getElementsByTagName("From")[0]
    dst = l.getElementsByTagName("To")[0]
    linkGuid = l.attributes["id"].nodeValue

    # enable the found subnet
    subnet = linksByID[linkGuid]['subnet']
    subnets.add(subnet)
    if not subnet in links:
        links[subnet] = {}

    for port in [src, dst]:
        guid = fmtID(
                port.getElementsByTagName("NodeGUID")[0].firstChild.nodeValue)
        if not guid in nodes[subnet]:
            print("Oups: node %s not found but in link" % guid)
        portNum = port.getElementsByTagName("PortNum")[0].firstChild.nodeValue
        link.append({'id': guid, 'port': portNum})

    # save the link in both ways
    for first in (0, 1):
        src = link[first]['id']
        print(src)
        dst = link[1-first]['id']
        currLink = {
                'hosts': (link[first], link[1-first]),
                'id': 2*linkID+first,
                'otherid': 2*linkID+1-first,
                'width': linksByID[linkGuid]['width'],
                'speed': linksByID[linkGuid]['speed'],
                'gbits': 100}
        linkID += 1
        if src not in links[subnet]:
            links[subnet][src] = {}
        if dst not in links[subnet][src]:
            links[subnet][src][dst] = []
        links[subnet][src][dst].append(currLink)

################################################################################
# Write file
for subnet in subnets:
    with open('netloc/OPA-%s-nodes.txt' % subnet,'w') as f:
        # Version
        f.write("1\n") # Version
        f.write("omnipath\n") # Subnet
        f.write("\n") # Path to hwloc
        f.write("%d\n" % len(nodes[subnet])) # Number of nodes

        # Nodes
        for node in nodes[subnet].values():
            # phyID,logID,type,partition,description,hostname
            line = "%s,%s,%d,%d,%s,%s" % (\
                    node['id'], node['id'], node['type'], 0,
                    node['description'], node['name'])
            f.write(line+"\n")

        # Nodes
        for src, dstLink in links[subnet].items():
            line = "%s" % src
            for dst, link in links[subnet][src].items():
                numRepeats = len(link)
                speed = 100*numRepeats
                # src,dest,speed,partitions,numLinks,
                line += ",%s,%d,%d,%d" % (dst, speed, 0, numRepeats)
                for l in link:
                    # id,port1,port2,
                    # width,speed,gbits,desc,
                    # other_way_id,partitions
                    line += ",%d,%s,%s,%s,%s,%s,%s,%d,%d" % (\
                            l['id'], l['hosts'][0]['port'], l['hosts'][1]['port'],
                            l['width'], l['speed'], l['gbits'], '',
                            l['otherid'], 0)
            f.write(line+"\n")
        # Partitions
        f.write(','.join(partitions)+"\n")

# debug XXX XXX XXX XXX XXX XXX XXX
for subnet in subnets:
    nodeKeys = set(nodes[subnet].keys())
    linkKeys = set(links[subnet].keys())
    print(subnet)
    print(list(nodeKeys-linkKeys))
