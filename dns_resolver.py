from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET
import time
"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "199.7.83.42"    # ICANN Root Server
DNS_PORT = 53

# method to modify the input domain name
def normalize_domain(domain: str) -> str:
    return domain.lower().strip('.') + '.'


cache = {}  # { domain: { "A": [ {value: ip, expiry: ts}, ... ] } } idea taken from grok AI
cache_id_map = {}  # {id: (domain, type)}

def update_cache(rr):
    """
    Store resource record in cache by type.
    """
    name = normalize_domain(str(rr.rname))
    rtype = QTYPE[rr.rtype]   # e.g. "A", "AAAA", "NS", "CNAME"
    rdata = str(rr.rdata)
    ttl = rr.ttl

    expiry = time.time() + ttl   # absolute timestamp when record expires

    # adding new entry to the cache
    if name not in cache:
        cache[name] = {}
    if rtype not in cache[name]:
        cache[name][rtype] = []

    cache[name][rtype].append({"value": rdata, "expiry": expiry})

def check_cache(domain, rtype="A"):
    """
    Check if a domain/rtype is in cache and not expired.
    Returns a list of valid cached records or None.
    """
    domain = normalize_domain(domain)
    # now compares time with ttl added expiry time
    now = time.time()

    if domain in cache and rtype in cache[domain]:
        # storing records of ip in a list
        records = []
        for entry in cache[domain][rtype]:
            if entry["expiry"] > now:
                records.append(entry["value"])
            else:
                print(f"Expired cache entry: {domain} {rtype} {entry['value']}")

        if records:
            return records

    return None

def cache_list():
    output = []
    idx = 1
    for cache_id, (domain, rtype) in sorted(cache_id_map.items()):
        values = check_cache(domain, rtype)
        for value in values:
            output.append(f"{idx}. {domain} ({rtype}): {value}")
            idx += 1
    return output

def cache_clear():
    global cache, cache_id_map
    cache = {}
    cache_id_map = {}

def cache_remove(idx):
    if idx <= 0 or idx > len(cache_id_map):
        return False
    cache_id = sorted(cache_id_map.keys())[idx-1]
    domain, rtype = cache_id_map[cache_id]
    del cache_id_map[cache_id]
    if domain in cache and rtype in cache[domain]:
        cache[domain][rtype] = []
        if not cache[domain]:
            del cache[domain]
    return True


def get_dns_record(udp_socket, domain: str, parent_server: str, record_type: str) -> list:
    
  """
  RFC1035 Section 4.1 Format
  
  The top level format of DNS message is divided into five sections:
  1. Header
  2. Question
  3. Answer
  4. Authority
  5. Additional
  """

    
    
    
  """
  Iterative DNS resolver: Follow referrals until answer or error.
  Returns list of values (e.g., IPs) or empty list on failure.
"""
  domain = normalize_domain(domain)
  #dynamically retrieving the attributes
  record_type_enum = getattr(QTYPE, record_type)
  current_server = parent_server

  while True:
        # Check cache first (for the target domain)
        cached = check_cache(domain, record_type)
        if cached:
            print(f"[CACHE HIT] {domain} {record_type} -> {cached}")
            return cached

        # Build and send query
        q = DNSRecord.question(domain, qtype = record_type)
        q.header.rd = 0   # Recursion Desired?  NO
        print("DNS query", repr(q))
        udp_socket.sendto(q.pack(), (current_server, DNS_PORT))
      
        try:
            pkt, _ = udp_socket.recvfrom(8192)
        except socket.timeout:
            print("Query timed out.")
            return []
        buff = DNSBuffer(pkt)
        header = DNSHeader.parse(buff)
        print("DNS header", repr(header))

        if q.header.id != header.id:
            print("Unmatched transaction")
            return []

        if header.rcode != RCODE.NOERROR:
            if header.rcode == RCODE.NXDOMAIN:
                print("This domain name does not exist. Please enter a valid domain name.")
            else:
                print("Query failed for format error or being refused or for other reasons.")
            return []

        # Parse the question section #2
        for k in range(header.q):
            q = DNSQuestion.parse(buff)
            print(f"Question-{k} {repr(q)}")

        # Parse the answer section #3
        answers = []
        for k in range(header.a):
            a = RR.parse(buff)
            print(f"Answer-{k} {repr(a)}")
            update_cache(a)
            if a.rtype == record_type_enum:
                answers.append(str(a.rdata))
                if record_type == 'A':
                    print("IP address")

        if answers:
            return answers

        # Parse the authority section #4 for NS referrals
        ns_list = []
        for k in range(header.auth):
            auth = RR.parse(buff)
            print(f"Authority-{k} {repr(auth)}")
            update_cache(auth)
            if auth.rtype == QTYPE.NS:
                ns_name = normalize_domain(str(auth.rdata))
                ns_list.append(ns_name)

        # Parse the additional section for records
        record_map = {}
        for k in range(header.ar):
            adr = RR.parse(buff)
            print(f"Additional-{k} {repr(adr)}")
            if adr.rtype == QTYPE.A:
                g_domain = normalize_domain(str(adr.rname))
                record_map[g_domain] = str(adr.rdata)
                update_cache(adr)  # Cache IPs

        # Select next server from first NS with glue or cached IP
        next_server = None
        if ns_list:
            ns_name = ns_list[0]  # Use first NS for simplicity
            next_server = record_map.get(ns_name)
            if not next_server:
                cached_glue = check_cache(ns_name, 'A')
                if cached_glue:
                    next_server = cached_glue[0]
                else:
                    print(f"Resolving IP for {ns_name}...")
                    glue_ip = get_dns_record(udp_socket, ns_name, parent_server, 'A')
                    if glue_ip:
                        next_server = glue_ip[0]

        if next_server:
            current_server = next_server
            print(f"Following referral to {current_server} for {domain}")
            continue  # Iterate to next level
        else:
            print("No suitable name server found in referral.")
            return []

  
if __name__ == '__main__':
    
    # Create a UDP socket with timeout
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.settimeout(5)  # 5 second timeout

    cache_counter = 0  # For sequential IDs in cache_id_map

    # Get all the .edu name servers from the ROOT SERVER
    while True:
        user_input = input("Enter a domain name, .list, .clear, .remove <idx>, or .exit > ").strip()

        if user_input == '.exit':
            break
        elif user_input == '.list':
            output = cache_list()
            if output:
                print("\n".join(output))
            else:
                print("Cache is empty.")
            continue
        elif user_input == '.clear':
            cache_clear()
            cache_counter = 0  # Reset counter too
            print("Cache cleared.")
            continue
        elif user_input.startswith('.remove '):
            try:
                idx = int(user_input.split(' ', 1)[1].strip())
                if cache_remove(idx):
                    print(f"Cache entry {idx} removed.")
                else:
                    print(f"Invalid index {idx}. Use .list to see entries.")
            except (ValueError, IndexError):
                print("Usage: .remove <idx> (e.g., .remove 1)")
            continue

        # Treat as domain
        domain_name = user_input
        if not domain_name:
            continue

        record_type = "A"

        # First check the cache
        cached = check_cache(domain_name, record_type)
        if cached:
            print(f"[CACHE HIT] {domain_name} {record_type} -> {cached}")
            continue  # Next query

        # Resolve iteratively
        results = get_dns_record(sock, domain_name, ROOT_SERVER, record_type)
        if results:
            print(f"Resolved {domain_name} {record_type} -> {results}")
            # Populate cache_id_map for list/remove
            cache_counter += 1
            cache_id_map[cache_counter] = (domain_name, record_type)
        else:
            print("Resolution failed.")

    sock.close()
