# RFC 7084 protocol tester

This software implement IPv6 tests on routers using the RFC 7084 requirements.

The Setup and steps for each test is described on Document: [Conformace Scenario](https://www.ipv6ready.org/docs/CE_Router_Conformance_Latest.pdf)

## Installation
```bash
git clone https://github.com/ronyjah/tcc_ronaldo
cd tcc_ronaldo
sudo su
source venv/bin/activate
python3 __main__.py -c .

```

## Usage

### List tests:
The basic requeriments to Routers IPv6 conformance and cover by RFC 7084 protocol  tester

#### WAN Group
- [x] 1.6.1: ROUTER SOLICITATION TRANSMISSION
- [x] 1.6.2: L FLAG PROCESSING Part.A
- [x] 1.6.2: L FLAG PROCESSING Part.B
- [x] 1.6.3: RECONFIGURE MESSAGE: Part A
- [x] 1.6.3: RECONFIGURE MESSAGE: Part B
- [x] 1.6.3: RECONFIGURE MESSAGE: Part C
- [x] 1.6.3: RECONFIGURE MESSAGE: Part D
- [x] 1.6.4: M FLAG PROCESSING 
- [x] 1.6.5: PREFIX DELEGATION SIZE
- [x] 1.6.6: M AND O FLAG FOR PREFIX DELEGATION Part A
- [x] 1.6.6: M AND O FLAG FOR PREFIX DELEGATION Part B
- [x] 1.6.7: DYNAMIC ROUTING PROTOCOL

#### LAN Group
- [x] 2.7.1: ASSIGNING PREFIXES TO LAN INTERFACES Part A
- [x] 2.7.1: ASSIGNING PREFIXES TO LAN INTERFACES Part B
- [x] 2.7.1: ASSIGNING PREFIXES TO LAN INTERFACES Part C
- [x] 2.7.2: ROUTE INFORMATION OPTION  Part A
- [x] 2.7.2: ROUTE INFORMATION OPTION  Part B
- [x] 2.7.3: NO PREFIXES DELEGATED Part A
- [x] 2.7.3: NO PREFIXES DELEGATED Part B
- [x] 2.7.3: NO PREFIXES DELEGATED Part C
- [x] 2.7.4: DNS INFORMATION IN ROUTER ADVERTISEMENT PART A
- [x] 2.7.4: DNS INFORMATION IN ROUTER ADVERTISEMENT PART B
- [x] 2.7.5: PREFIX CHANGE PART A
- [x] 2.7.5: PREFIX CHANGE PART B
- [x] 2.7.5: PREFIX CHANGE PART C
- [x] 2.7.5: PREFIX CHANGE PART D
- [x] 2.7.6: UNKNOWN PREFIX
- [x] 2.7.7: UNIQUE LOCAL ADDRESS PREFIX PART A
- [x] 2.7.7: UNIQUE LOCAL ADDRESS PREFIX PART B
- [x] 2.7.7: UNIQUE LOCAL ADDRESS PREFIX PART C

#### FORWARDING Group
- [x] 3.2.1: IPV6 FORWARDING BEFORE ADDRESS ACQUISITION PART A
- [x] 3.2.1: IPV6 FORWARDING BEFORE ADDRESS ACQUISITION PART B
- [x] 3.2.2: NO DEFAULT ROUTE PART A
- [x] 3.2.2: NO DEFAULT ROUTE PART B
- [x] 3.2.3: FORWARDING LOOPS PART A
- [x] 3.2.3: FORWARDING LOOPS PART B
- [x] 3.2.4: UNIQUE LOCAL ADDRESS FORWARDING

### Todo
- [ ] User Interface
- [ ] automated pcap capture
