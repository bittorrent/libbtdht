import dpkt, bencode, struct, traceback, sys, argparse, socket

listMax = 40

bad = 0
no_version = 0

non_ut = {}
versionIps = {}

def bootstrapCount(fp):
    global no_version, bad, non_ut, versionIps

    pcap = dpkt.pcap.Reader(fp)

    i = 0
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        try:
            decoded = bencode.bdecode(tcp.data)
        except:
            bad += 1
            continue
        
        version = decoded.get("v")
        if not version:
            no_version += 1
            continue

        if version[0:2] != "UT":
            try: non_ut[version] += 1
            except: non_ut[version] = 1
            continue

        #Read the version
        version = version[2:]        
        unpackedVersion = struct.unpack('>H', version)
        unpackedVersion = unpackedVersion[0]
        
        #Get the remote IP address
        src_ip_addr_str = socket.inet_ntoa(ip.src)

        #Add it to the structured map.
        try: versionIps[unpackedVersion][src_ip_addr_str] += 1
        except: 
            try: versionIps[unpackedVersion][src_ip_addr_str] = 1
            except: versionIps[unpackedVersion] = { src_ip_addr_str: 1 }
        
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
        versionPairs.append([build, sum(ipMap.values()), len(ipMap)])

    print
    print "======================================================"
    print "UT Builds (top " + str(listMax) + ")"
    print "======================================================"
    vpSorted = sorted(versionPairs, key=lambda pair: pair[1], reverse=True)
    for idx, pair in enumerate(vpSorted):
        if idx > listMax: break
        print "Build " + str(pair[0]) + ":\t" + str(pair[1]) + " (" + str(pair[2]) + " unique IPs)"

    nonUtPairs = []
    for k,v in non_ut.iteritems():
        nonUtPairs.append([k, v])

    print
    print "======================================================"
    print "Other Clients (top " + str(listMax) + ")"
    print "======================================================"
    nutSorted = sorted(nonUtPairs, key=lambda pair: pair[1], reverse=True)
    for idx, pair in enumerate(nutSorted):
        if idx > listMax: break
        
        ver = pair[0]
        try: 
            unpackedVersion = struct.unpack('>H', ver[2:])
            ver = ver[0:2] + str(unpackedVersion[0])
        except:
            ver = "Unknown " + ver.strip()
            
        print str(ver) + ":    \t" + str(pair[1])

    print
    print "======================================================"
    print "Miscellaneous"
    print "======================================================"
    print "Bad:       \t" + str(bad)
    print "No Version:\t" + str(no_version)
    
    print
    print
