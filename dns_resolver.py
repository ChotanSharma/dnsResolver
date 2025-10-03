from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "199.7.83.42"    # ICANN Root Server
DNS_PORT = 53

# method to modify the input domain name
def normalize_domain(domain: str) -> str:
    return domain.lower().strip('.') + '.'


def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
  q = DNSRecord.question(domain, qtype = record_type)
  q.header.rd = 0   # Recursion Desired?  NO
  print("DNS query", repr(q))
  udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
  pkt, _ = udp_socket.recvfrom(8192)
  buff = DNSBuffer(pkt)
  
  """
  RFC1035 Section 4.1 Format
  
  The top level format of DNS message is divided into five sections:
  1. Header
  2. Question
  3. Answer
  4. Authority
  5. Additional
  """

  # a variable to store the the ip address
  ip_addresses = []  
  name_to_ips = {}  # Dictionary to map names to their IP addresses
  
  header = DNSHeader.parse(buff)
  print("DNS header", repr(header))
  if q.header.id != header.id:
    print("Unmatched transaction")
    return
  if header.rcode != RCODE.NOERROR:
    print("Query failed")
    return

  # Parse the question section #2
  for k in range(header.q):
    q = DNSQuestion.parse(buff)
    print(f"Question-{k} {repr(q)}")
    
  # Parse the answer section #3
  for k in range(header.a):
    a = RR.parse(buff)
    print(f"Answer-{k} {repr(a)}")
    if a.rtype == QTYPE.A:
      print("IP address")
      ip_addresses.append(str(a.rdata)) 

  # Parse the authority section #4
  for k in range(header.auth):
    auth = RR.parse(buff)
    print(f"Authority-{k} {repr(auth)}")
      
  # Parse the additional section #5
  for k in range(header.ar):
    adr = RR.parse(buff)
    print(f"Additional-{k} {repr(adr)} Name: {adr.rname}")
    if adr.rtype == QTYPE.A:  # Only grab IPv4 A records
            name = str(adr.rname).rstrip('.')  # Clean name, e.g., 'a.edu-servers.net'
            if name not in name_to_ips:
                name_to_ips[name] = []
            name_to_ips[name].append(str(adr.rdata))  # Add IP to list for that name
            print(f"Grabbed IP '{adr.rdata}' for '{name}'")
    # Return the IP address from the answer section
  return ip_addresses, name_to_ips

  
if __name__ == '__main__':
  # Create a UDP socket
  sock = socket(AF_INET, SOCK_DGRAM)
  # Get all the .edu name servers from the ROOT SERVER
  while True:
    domain_name = input("Enter a domain name or .exit > ").strip()

    if domain_name == '.exit':
            break

    # First check the cache
   
    # Resolve iteratively
    results, name_to_ips = get_dns_record(sock, domain_name, ROOT_SERVER, 'A')# hard coding the record type to 
    if results:
        print(f"Resolved {domain_name}  -> {results}")
    else:
        print("Resolution failed.")
        if name_to_ips:
            print(f"Referral name-to-IPs: {name_to_ips}")
            # Optional: Example usage for next query
            first_name = next(iter(name_to_ips))
            first_ip = name_to_ips[first_name][0]
            print(f"Next server example: {first_name} -> {first_ip}")
        else:
            print("No referrals found.")