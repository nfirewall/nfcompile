from NftObjects import AcceptAction, Chain, DropAction, JumpAction, Match, Rule, Table
from _helpers import default
import json

jsn = json.load(open("rulebase.json", "r"))
options = jsn["options"]
rulebase = jsn["rulebase"]

defaultFilterChains = ["tcp", "udp", "icmp", "icmpv6", "icmp-local", "icmpv6-local", "input", "forward", "output"]

rules = []
chains = []
tables = []

namedChains = {}

# Create table

_table = Table("inet", "inet")
tables.append(_table)

if options["default_drop"]:
    policy = "drop"
else:
    policy = "accept"

# Create chains
for chain in defaultFilterChains:
    _chain = Chain("inet", chain, _table)
    if chain in ["input", "forward", "output"]:
        _chain.type = "filter"
        _chain.hook = chain
        _chain.priority = 0
        _chain.default = policy
    chains.append(_chain)
    namedChains[chain] = _chain

# Stateful firewall?
if options["stateful"]:
    _rule = Rule(namedChains["input"], "-1", log=False)
    _rule.action = AcceptAction()
    _rule.add_match(Match({"ct": { "key": "state"}}, "in", ["established", "related"]))
    rules.append(_rule)


# Local traffic allowed
_rule = Rule(namedChains["input"], "-2", log=False)
_rule.action = AcceptAction()
_rule.add_match(Match({"meta": {"key": "iif"}}, "==", "lo"))
_rule.action = AcceptAction()
rules.append(_rule)

# Local pings?
if options["allow_local_pings"]:
    action = AcceptAction()
else:
    action = DropAction()

_rule = Rule(namedChains["icmp-local"], "-3", log=False)
_rule.action = action
rules.append(_rule)
_rule = Rule(namedChains["icmpv6-local"], "-3", log=False)
_rule.action = action
rules.append(_rule)

# Forwarded pings?

if options["allow_pings"]:
    action = AcceptAction()
else:
    action = DropAction()

_rule = Rule(namedChains["icmp"], "-4", log=False)
_rule.action = action
rules.append(_rule)
_rule = Rule(namedChains["icmpv6"], "-4", log=False)
_rule.action = action
rules.append(_rule)


# IPv4 TCP
_rule = Rule(namedChains["input"], "", log=False)
_rule.action = JumpAction(namedChains["tcp"])
_rule.add_match(Match({"payload": {"protocol": "ip", "field": "protocol"}}, "==", "tcp"))
rules.append(_rule)
# IPv4 UDP
_rule = Rule(namedChains["input"], "", log=False)
_rule.action = JumpAction(namedChains["udp"])
_rule.add_match(Match({"payload": {"protocol": "ip", "field": "protocol"}}, "==", "udp"))
rules.append(_rule)

# IPv6 TCP
_rule = Rule(namedChains["input"], "", log=False)
_rule.action = JumpAction(namedChains["tcp"])
_rule.add_match(Match({"payload": {"protocol": "ip6", "field": "nexthdr"}}, "==", "tcp"))
rules.append(_rule)
# IPv6 UDP
_rule = Rule(namedChains["input"], "", log=False)
_rule.action = JumpAction(namedChains["udp"])
_rule.add_match(Match({"payload": {"protocol": "ip6", "field": "nexthdr"}}, "==", "udp"))
rules.append(_rule)

# IPv4 TCP
_rule = Rule(namedChains["forward"], "", log=False)
_rule.action = JumpAction(namedChains["tcp"])
_rule.add_match(Match({"payload": {"protocol": "ip", "field": "protocol"}}, "==", "tcp"))
rules.append(_rule)
# IPv4 UDP
_rule = Rule(namedChains["forward"], "", log=False)
_rule.action = JumpAction(namedChains["udp"])
_rule.add_match(Match({"payload": {"protocol": "ip", "field": "protocol"}}, "==", "udp"))
rules.append(_rule)

# IPv6 TCP
_rule = Rule(namedChains["forward"], "", log=False)
_rule.action = JumpAction(namedChains["tcp"])
_rule.add_match(Match({"payload": {"protocol": "ip6", "field": "nexthdr"}}, "==", "tcp"))
rules.append(_rule)
# IPv6 UDP
_rule = Rule(namedChains["forward"], "", log=False)
_rule.action = JumpAction(namedChains["udp"])
_rule.add_match(Match({"payload": {"protocol": "ip6", "field": "nexthdr"}}, "==", "udp"))
rules.append(_rule)

# Local ICMP
_rule = Rule(namedChains["input"], "", log=False)
_rule.action = JumpAction(namedChains["icmp-local"])
_rule.add_match(Match({"payload": {"protocol": "icmp", "field": "type"}}, "==", {"set": ["destination-unreachable", "router-advertisement", "router-solicitation", "time-exceeded", "parameter-problem"]}))
rules.append(_rule)

# Local ICMPv6
_rule = Rule(namedChains["input"], "", log=False)
_rule.action = JumpAction(namedChains["icmpv6-local"])
_rule.add_match(Match({"payload": {"protocol": "icmpv6", "field": "type"}}, "==", {"set": ["destination-unreachable", "packet-too-big", "time-exceeded", "parameter-problem", "mld-listener-query", "mld-listener-report", "mld-listener-done", "nd-router-solicit", "nd-router-advert", "nd-neighbor-solicit", "nd-neighbor-advert", "ind-neighbor-solicit", "ind-neighbor-advert", "mld2-listener-report"]}))
rules.append(_rule)

# Forwarded ICMP
_rule = Rule(namedChains["forward"], "", log=False)
_rule.action = JumpAction(namedChains["icmp"])
_rule.add_match(Match({"payload": {"protocol": "icmp", "field": "type"}}, "==", {"set": ["destination-unreachable", "router-advertisement", "router-solicitation", "time-exceeded", "parameter-problem"]}))
rules.append(_rule)

# Forwarded ICMPv6
_rule = Rule(namedChains["forward"], "", log=False)
_rule.action = JumpAction(namedChains["icmpv6"])
_rule.add_match(Match({"payload": {"protocol": "icmpv6", "field": "type"}}, "==", {"set": ["destination-unreachable", "packet-too-big", "time-exceeded", "parameter-problem", "mld-listener-query", "mld-listener-report", "mld-listener-done", "nd-router-solicit", "nd-router-advert", "nd-neighbor-solicit", "nd-neighbor-advert", "ind-neighbor-solicit", "ind-neighbor-advert", "mld2-listener-report"]}))
rules.append(_rule)

for rule in rulebase:
    _rule = None
    proto = rule["protocol"]
    try:
        _rule = Rule(namedChains[proto], rule["id"])
    except KeyError:
        raise Exception("Invalid protocol: {}".format(proto))
    if rule["action"] == "accept":
        _rule.action = AcceptAction()
    elif rule["action"] == "drop":
        _rule.action == DropAction()
    else:
        raise Exception("Invalid action")
    
    try:
        src = rule["src"]
        dst = rule["dst"]
        sport = rule["sport"]
        dport = rule["dport"]
        interface = rule["interface"]
    except KeyError:
        raise Exception("Invalid Rule: {}")

    # Sanity
    if src == "any":
        src = None
    if dst == "any":
        dst = None
    if sport == "any":
        sport = None
    if dport == "any":
        dport = None
    if interface == "any":
        interface = None


    # Src
    if type(src) is list:
        # This is a multiple
        _match = Match({"payload": {"protocol": "ip", "field": "saddr"}}, "in", src)
        _rule.add_match(_match)
    elif src:
        _match = Match({"payload": {"protocol": "ip", "field": "saddr"}}, "==", src)
        _rule.add_match(_match)
    
    # Dest
    if type(dst) is list:
        # This is a multiple
        _match = Match({"payload": {"protocol": "ip", "field": "daddr"}}, "in", dst)
        _rule.add_match(_match)
    elif dst:
        _match = Match({"payload": {"protocol": "ip", "field": "daddr"}}, "==", dst)
        _rule.add_match(_match)
    
    # Sport
    if sport is list:
        # This is a multiple
        _match = Match({"payload": {"protocol": "tcp", "field": "sport"}}, "in", rule["sport"])
        _rule.add_match(_match)
    elif sport:
        _match = Match({"payload": {"protocol": "tcp", "field": "sport"}}, "==", rule["sport"])
        _rule.add_match(_match)
    
    # Dport
    if dport is list:
        # This is a multiple
        _match = Match({"payload": {"protocol": "tcp", "field": "dport"}}, "in", rule["dport"])
        _rule.add_match(_match)
    elif dport:
        _match = Match({"payload": {"protocol": "tcp", "field": "dport"}}, "==", rule["dport"])
        _rule.add_match(_match)
        
    # Interface
    if interface:
        _match = Match({"meta": {"key": "iif"}}, "==", interface)
        _rule.add_match(_match)
    rules.append(_rule)
    

res = {"nftables": [{"flush": {"ruleset": None}}]}

for table in tables:
    res["nftables"].append({"table": table})
for chain in chains:
    res["nftables"].append({"chain": chain})
for rule in rules:
    res["nftables"].append({"rule": rule})

print(json.dumps(res))