# Iterative DNS Resolver

A simple, iterative DNS resolver implemented in Python using the **dnslib** library.  
This script simulates a non-recursive DNS client by starting queries at a root name server,  
following NS referrals down the hierarchy (**root → TLD → authoritative**), and resolving **A records** for given domains.  

It includes a basic caching system to store and reuse responses, with commands to manage the cache.

---

## Features

- **Iterative Resolution**: Follows DNS referrals manually without relying on recursive queries (RD=0).  
- **Caching**: Stores resolved records (A, NS, etc.) with TTL-based expiry. Supports cache hits for faster subsequent queries.  
- **Cache Management**: Interactive commands to list, clear, or remove specific cache entries.  
- **Error Handling**: Handles NXDOMAIN, timeouts, unmatched transactions, and referral failures.  
- 

---

## Requirements

- Python **3.6+** (tested with 3.12)  
- `dnslib`: For DNS message parsing/packing.  

Install with:

```bash
pip install dnslib
