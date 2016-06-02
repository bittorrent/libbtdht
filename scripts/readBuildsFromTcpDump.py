/*
Copyright 2016 BitTorrent Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import dpkt, bencode, struct, traceback, sys, argparse, socket

listMax = 40

bad = 0
no_version = 0

nonUtIps = {}
versionIps = {}
bandwidth = { "in":{}, "out":{}, "bad":{ "noId":0, "notEncoded":0 } }

def bootstrapCount(fp):
    global no_version, bad, nonUtIps, versionIps

    pcap = dpkt.pcap.Reader(fp)

    i = 0
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        #Get the remote IP address and location identifier
        try:
            src_ip_addr_str = socket.inet_ntoa(ip.src)
            locId = src_ip_addr_str + ":" + str(tcp.sport)
        except:
            try: bandwidth["bad"]["noId"] += len(tcp.data)
            except: pass
            continue

        try:
            decoded = bencode.bdecode(tcp.data)
        except:
            bandwidth["bad"]["notEncoded"] += len(tcp.data)

            bad += 1
            continue
        
        version = decoded.get("v")
        if not version:
            #No version, we assume it's outbound.  Change the locId
            src_ip_addr_str = socket.inet_ntoa(ip.dst)
            locId = src_ip_addr_str + ":" + str(tcp.dport)

            #Set outbound bandwidth
            try: bandwidth["out"][locId] += len(tcp.data)
            except: bandwidth["out"][locId] = len(tcp.data)

            no_version += 1
            continue
        
        #We have a version, we assume it's inbound.
        try: bandwidth["in"][locId] += len(tcp.data)
        except: bandwidth["in"][locId] = len(tcp.data)

        if version[0:2] != "UT":
            try: nonUtIps[version][locId] += 1
            except: 
                try: nonUtIps[version][locId] = 1
                except: nonUtIps[version] = { locId: 1 }

            continue

        #Read the version
        version = version[2:]        
        unpackedVersion = struct.unpack('>H', version)
        unpackedVersion = unpackedVersion[0]
        
        #Add it to the structured map.
        try: versionIps[unpackedVersion][locId] += 1
        except: 
            try: versionIps[unpackedVersion][locId] = 1
            except: versionIps[unpackedVersion] = { locId: 1 }
        
        i += 1
        if (i % 100) == 0:
            sys.stdout.write(".")
            sys.stdout.flush()
        
        """
        print '============================'
        print tcp.sport
        print '============================'
        print decoded
        print '============================'
        print version
        print '============================'
        print unpackedVersion
        print '============================'
        print
        print
        """

    fp.close()
    print


######################################################
if __name__ == '__main__':
    #Parse the args
    parser = argparse.ArgumentParser()
    parser.add_argument(action="store", nargs='?', dest="pcapPath", help="The tcpdump PCAP file", metavar="[pcap file path]")
    args = parser.parse_args()

    #Have enough args?
    if not args.pcapPath:
        print "Usage: readBuildsFromTcpDump.py [pcap file path]\n"
        exit(1)

    try: fp = open(args.pcapPath)
    except:
        print "Cannot open '" + args.pcapPath + "'"
        exit(1)

    try: bootstrapCount(fp)
    except: 
        traceback.print_exc()
    
    versionPairs = []
    for build, ipMap in versionIps.iteritems():
        bandwidthOut = 0
        for locId in ipMap.keys():
            bandwidthOut += bandwidth["out"].get(locId, 0)

        versionPairs.append([build, sum(ipMap.values()), len(ipMap), bandwidthOut])

    print
    print "======================================================"
    print "UT Builds (top " + str(listMax) + ")"
    print "======================================================"
    vpSorted = sorted(versionPairs, key=lambda pair: pair[1], reverse=True)
    for idx, pair in enumerate(vpSorted):
        if idx > listMax: break

        ver = pair[0]
        out = pair[3]
        outPer = out / pair[1]
        ratio = round(float(pair[1])/pair[2], 2)

        print "Build " + str(ver) + ":\t\t" +\
            str(pair[1]) + " // " +\
            str(pair[2]) + " unique // " +\
            str(ratio) + " ratio // " +\
            str(out) + " out // " +\
            str(outPer) + " per request"

    nonUtPairs = []
    for build, ipMap in nonUtIps.iteritems():
        bandwidthOut = 0
        for locId in ipMap.keys():
            bandwidthOut += bandwidth["out"].get(locId, 0)

        nonUtPairs.append([build, sum(ipMap.values()), len(ipMap), bandwidthOut])

    print
    print "======================================================"
    print "Other Clients (top " + str(listMax) + ")"
    print "======================================================"
    nutSorted = sorted(nonUtPairs, key=lambda pair: pair[1], reverse=True)
    for idx, pair in enumerate(nutSorted):
        if idx > listMax: break
        
        ver = pair[0]
        out = pair[3]
        outPer = out / pair[1]
        ratio = round(pair[1]/pair[2], 2)

        try: 
            unpackedVersion = struct.unpack('>H', ver[2:])
            ver = ver[0:2] + str(unpackedVersion[0])
        except:
            ver = "??? " + ver.strip()
            
        print "Build " + str(ver) + ":\t\t" +\
            str(pair[1]) + " // " +\
            str(pair[2]) + " unique // " +\
            str(ratio) + " ratio // " +\
            str(out) + " out // " +\
            str(outPer) + " per request"

    print
    print "======================================================"
    print "Miscellaneous"
    print "======================================================"
    print "Bad:       \t" + str(bad)
    print "No Version:\t" + str(no_version)
    
    print
    print

    print bandwidth["bad"]
