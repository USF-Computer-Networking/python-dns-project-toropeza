from scapy.all import *
from threading import Thread

# Dictionary mapping all of the routes
routes = {}


def get_dns_resp(packet):
    # https://thepacketgeek.com/scapy-p-09-scapy-and-dns/
    return sr1(IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=packet[DNSQR].qname)), verbose=False)


def add_dns_route_entry(packet, dns_resp):
    routelist = []
    for x in range(dns_resp[DNS].ancount):
        if dns_resp[DNSRR] != None:
            routelist.append(dns_resp[DNSRR][x].rdata)
    routes[packet[DNSQR].qname] = routelist


def add_packet_route(packet):
    dns_resp = get_dns_resp(packet)
    add_dns_route_entry(packet, dns_resp)


def packet_found(packet):
    if packet.haslayer(DNS):
        if packet.__contains__(DNSQR):
            if routes.get(packet[DNSQR].qname) == None:
                add_packet_route(packet)


def run_sniff():
    print "Sniffing\n"
    sniff(prn=packet_found)


def usage():
    print "Available actions"
    print "     -h (Help)"
    print "     ls (Lists all of the available DNS Routes)"
    print "     route <domain> (Prints the DNS route for the given domain)"
    print "     graph (Prints a full graph of all sniffed DNS records)"


def ls():
    if not any(routes):
        print "No routes"
        return

    for entry in routes:
        print entry


def print_route(domain):
    route = routes.get(domain)
    sys.stdout.write('\t')
    for stop in route:
        sys.stdout.write(stop + " --> ")
    sys.stdout.write(domain + '\n')
    sys.stdout.write('\t')
    sys.stdout.write('Details:' +'\n')
    sys.stdout.write('\t\tHostname: ' + domain + '\n')
    sys.stdout.write('\t\tHops: ' + str(len(route)))
    sys.stdout.flush()


def print_graph():
    print "DNS GRAPH\n"
    for domain in routes:
        print_route(domain)
        print '\n'
        print "\t------------\n"

if __name__ == '__main__':
    thread = Thread(target=run_sniff)
    thread.start()

    running = True
    while (running):
        print "Enter command or help for more info"
        action = raw_input()
        if action == "help":
            usage()
        elif action == "ls":
            ls()
        elif action == "graph":
            print_graph()
        elif action.startswith("route"):
            argv = action.split(" ")
            if len(argv) != 2:
                usage()
                continue
            domain = argv[1]
            print_route(domain)
        else:
            print "Invalid command"
            usage()
