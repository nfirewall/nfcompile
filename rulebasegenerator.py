from NftObjects import AcceptAction, Chain, DropAction, JumpAction, Match, Rule, Table, Set
import json
from ipaddress import ip_network
import sys

def create_tables() -> list:
    # Create table
    tables = []
    _table = Table("inet", "inet_table")
    tables.append(_table)
    return tables

def create_chains(options, table) -> dict:
    # Create chains
    chains = {}
    if options["default_drop"]:
        policy = "drop"
    else:
        policy = "accept"
    for chain in defaultFilterChains:
        _chain = Chain("inet", "{}_chain".format(chain), table)
        if chain in ["input", "forward", "output"]:
            _chain.type = "filter"
            _chain.hook = chain
            _chain.priority = 0
            if chain in ["input", "forward"]:
                _chain.default = policy
        chains[chain] = _chain
    return chains

def set_options(options: dict, rules: list, chains: dict) -> None:
    # Stateful firewall?
    if options["stateful"]:
        _rule = Rule(chains["input"], "-1", log=False)
        _rule.action = AcceptAction()
        _rule.add_match(Match({"ct": { "key": "state"}}, "in", ["established", "related"]))
        rules.append(_rule)


    # Localhost traffic allowed
    _rule = Rule(chains["input"], "-2", log=False)
    _rule.add_match(Match({"meta": {"key": "iif"}}, "==", "lo"))
    _rule.action = AcceptAction()
    rules.append(_rule)

    # Local pings?
    if options["allow_local_pings"]:
        action = AcceptAction()
    else:
        action = DropAction()

    _rule = Rule(chains["icmp-local"], "-3", log=False)
    _rule.action = action
    rules.append(_rule)
    _rule = Rule(chains["icmpv6-local"], "-3", log=False)
    _rule.action = action
    rules.append(_rule)

    # Forwarded pings?

    if options["allow_pings"]:
        action = AcceptAction()
    else:
        action = DropAction()

    _rule = Rule(chains["icmp"], "-4", log=False)
    _rule.action = action
    rules.append(_rule)
    _rule = Rule(chains["icmpv6"], "-4", log=False)
    _rule.action = action
    rules.append(_rule)

def create_jumps(rules) -> None:
    # IPv4 TCP
    _rule = Rule(chains["input"], "", log=False)
    _rule.action = JumpAction(chains["tcp"])
    _rule.add_match(Match({"payload": {"protocol": "ip", "field": "protocol"}}, "==", "tcp"))
    rules.append(_rule)
    # IPv4 UDP
    _rule = Rule(chains["input"], "", log=False)
    _rule.action = JumpAction(chains["udp"])
    _rule.add_match(Match({"payload": {"protocol": "ip", "field": "protocol"}}, "==", "udp"))
    rules.append(_rule)

    # IPv6 TCP
    _rule = Rule(chains["input"], "", log=False)
    _rule.action = JumpAction(chains["tcp"])
    _rule.add_match(Match({"payload": {"protocol": "ip6", "field": "nexthdr"}}, "==", "tcp"))
    rules.append(_rule)
    # IPv6 UDP
    _rule = Rule(chains["input"], "", log=False)
    _rule.action = JumpAction(chains["udp"])
    _rule.add_match(Match({"payload": {"protocol": "ip6", "field": "nexthdr"}}, "==", "udp"))
    rules.append(_rule)

    # IPv4 TCP
    _rule = Rule(chains["forward"], "", log=False)
    _rule.action = JumpAction(chains["tcp"])
    _rule.add_match(Match({"payload": {"protocol": "ip", "field": "protocol"}}, "==", "tcp"))
    rules.append(_rule)
    # IPv4 UDP
    _rule = Rule(chains["forward"], "", log=False)
    _rule.action = JumpAction(chains["udp"])
    _rule.add_match(Match({"payload": {"protocol": "ip", "field": "protocol"}}, "==", "udp"))
    rules.append(_rule)

    # IPv6 TCP
    _rule = Rule(chains["forward"], "", log=False)
    _rule.action = JumpAction(chains["tcp"])
    _rule.add_match(Match({"payload": {"protocol": "ip6", "field": "nexthdr"}}, "==", "tcp"))
    rules.append(_rule)
    # IPv6 UDP
    _rule = Rule(chains["forward"], "", log=False)
    _rule.action = JumpAction(chains["udp"])
    _rule.add_match(Match({"payload": {"protocol": "ip6", "field": "nexthdr"}}, "==", "udp"))
    rules.append(_rule)

    # Local ICMP
    _rule = Rule(chains["input"], "", log=False)
    _rule.action = JumpAction(chains["icmp-local"])
    _rule.add_match(Match({"payload": {"protocol": "icmp", "field": "type"}}, "==", {"set": ["destination-unreachable", "router-advertisement", "router-solicitation", "time-exceeded", "parameter-problem"]}))
    rules.append(_rule)

    # Local ICMPv6
    _rule = Rule(chains["input"], "", log=False)
    _rule.action = JumpAction(chains["icmpv6-local"])
    _rule.add_match(Match({"payload": {"protocol": "icmpv6", "field": "type"}}, "==", {"set": ["destination-unreachable", "packet-too-big", "time-exceeded", "parameter-problem", "mld-listener-query", "mld-listener-report", "mld-listener-done", "nd-router-solicit", "nd-router-advert", "nd-neighbor-solicit", "nd-neighbor-advert", "ind-neighbor-solicit", "ind-neighbor-advert", "mld2-listener-report"]}))
    rules.append(_rule)

    # Forwarded ICMP
    _rule = Rule(chains["forward"], "", log=False)
    _rule.action = JumpAction(chains["icmp"])
    _rule.add_match(Match({"payload": {"protocol": "icmp", "field": "type"}}, "==", {"set": ["destination-unreachable", "router-advertisement", "router-solicitation", "time-exceeded", "parameter-problem"]}))
    rules.append(_rule)

    # Forwarded ICMPv6
    _rule = Rule(chains["forward"], "", log=False)
    _rule.action = JumpAction(chains["icmpv6"])
    _rule.add_match(Match({"payload": {"protocol": "icmpv6", "field": "type"}}, "==", {"set": ["destination-unreachable", "packet-too-big", "time-exceeded", "parameter-problem", "mld-listener-query", "mld-listener-report", "mld-listener-done", "nd-router-solicit", "nd-router-advert", "nd-neighbor-solicit", "nd-neighbor-advert", "ind-neighbor-solicit", "ind-neighbor-advert", "mld2-listener-report"]}))
    rules.append(_rule)

def parse_rule(rule: dict, chains: dict, sets: dict) -> list[Rule]:
    _rule = None
    _returnRules = []
    proto = rule["protocol"]
    try:
        _rule = Rule(chains[proto], rule["id"])
    except KeyError:
        raise Exception("Invalid protocol: {}".format(proto))
    if rule["action"] == "accept":
        action = AcceptAction()
    elif rule["action"] == "drop":
        action = DropAction()
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
    
    if type(src) is not list:
        src = [src]
    if type(dst) is not list:
        dst = [dst]
    if type(sport) is not list:
        sport = [sport]
    if type(dport) is not list:
        dport = [dport]
    
    for source in src:
        for destination in dst:
            for source_port in sport:
                for destination_port in dport:
                    _rules = [
                        Rule(chains[proto], rule["id"]),
                        Rule(chains[proto], rule["id"]),
                        Rule(chains[proto], rule["id"]),
                        Rule(chains[proto], rule["id"])
                    ]
                    _rulesToUse = []
                    if source:
                        # Source address is not None
                        try:
                            sets["{}_v4".format(source)]
                            found = True
                            _match = Match({"payload": {"protocol": "ip", "field": "saddr"}}, "==", "@{}_v4".format(source))
                            _rules[0].add_match(_match)
                            _rules[2].add_match(_match)
                            _rulesToUse.append(0)
                        except KeyError:
                            pass
                        
                        try:
                            sets["{}_v6".format(source)]
                            found = True
                            _match = Match({"payload": {"protocol": "ip6", "field": "saddr"}}, "==", "@{}_v6".format(source))
                            _rules[1].add_match(_match)
                            _rules[3].add_match(_match)
                            _rulesToUse.append(1)
                        except KeyError:
                            pass
                        if not found:
                            raise Exception("Invalid source: {}".format(source))
                    
                    if destination:
                        # destination address is not None
                        try:
                            sets["{}_v4".format(destination)]
                            found = True
                            _match = Match({"payload": {"protocol": "ip", "field": "daddr"}}, "==", "@{}_v4".format(destination))
                            _rules[0].add_match(_match)
                            _rules[2].add_match(_match)
                            _rulesToUse.append(2)
                        except KeyError:
                            pass
                        
                        try:
                            sets["{}_v6".format(destination)]
                            found = True
                            _match = Match({"payload": {"protocol": "ip6", "field": "daddr"}}, "==", "@{}_v6".format(destination))
                            _rules[1].add_match(_match)
                            _rules[3].add_match(_match)
                            _rulesToUse.append(3)
                        except KeyError:
                            pass
                        if not found:
                            raise Exception("Invalid destination: {}".format(src))
                        _rule.add_match(_match)

                    if source_port:
                        # source port is not None
                        found = False
                        try:
                            sets[source_port]
                            if sets[source_port].protocol == proto:
                                _match = Match({"payload": {"protocol": proto, "field": "sport"}}, "==", "@{}".format(source_port))
                                found = True
                        except KeyError:
                            try:
                                sets["{}_{}".format(source_port, proto)]
                                _match = Match({"payload": {"protocol": proto, "field": "sport"}}, "==", "@{}".format("{}_{}".format(source_port, proto)))
                                found = True
                            except KeyError:
                                pass
                        if not found:
                            raise Exception("Invalid sport: {}".format(source_port))
                        _rules[0].add_match(_match)
                        _rules[1].add_match(_match)
                        _rules[2].add_match(_match)
                        _rules[3].add_match(_match)
                    
                    if destination_port:
                        # destination port is not None
                        found = False
                        try:
                            sets[destination_port]
                            if sets[destination_port].protocol == proto:
                                _match = Match({"payload": {"protocol": proto, "field": "dport"}}, "==", "@{}".format(destination_port))
                                found = True
                        except KeyError:
                            try:
                                sets["{}_{}".format(destination_port, proto)]
                                _match = Match({"payload": {"protocol": proto, "field": "dport"}}, "==", "@{}".format("{}_{}".format(destination_port, proto)))
                                found = True
                            except KeyError:
                                pass
                        if not found:
                            raise Exception("Invalid dport: {}".format(destination_port))
                        _rules[0].add_match(_match)
                        _rules[1].add_match(_match)
                        _rules[2].add_match(_match)
                        _rules[3].add_match(_match)
                    if len(_rulesToUse) == 0:
                        _rulesToUse.append(0)
                    for rulenumber in _rulesToUse:
                        _rule = _rules[rulenumber]
                        _rule.action = action
                        _returnRules.append(_rule)
    return _returnRules

def parse_host(host: dict, table: Table, sets: dict) -> None:
    try:
        name = host["name"]
        type = host["type"]
    except KeyError:
        raise Exception("Invalid host")
    
    if not type in ["hostv4", "hostv6", "hostv4v6"]:
        raise Exception("Invalid Host: {}".format(name))
    
    if type in ["hostv4", "hostv4v6"]:
        try:
            v4address = host["valuev4"]
        except KeyError:
            raise Exception("Invalid Host: {}".format(name))
        _set = Set("{}_v4".format(name), "inet", "ipv4_addr", table)
        _set.add_member(v4address)
        sets["{}_v4".format(name)] = _set
    
    if type in ["hostv6", "hostv4v6"]:
        try:
            v6address = host["valuev6"]
        except KeyError:
            raise Exception("Invalid Host: {}".format(name))
        _set = Set("{}_v6".format(name), "inet", "ipv6_addr", table)
        _set.add_member(v6address)
        sets["{}_v6".format(name)] = _set

def parse_network(network: dict, table: Table, sets: dict) -> None:
    try:
        name = network["name"]
        type = network["type"]
    except KeyError:
        raise Exception("Invalid Network")
    
    if not type in ["networkv4", "networkv6", "networkv4v6"]:
        raise Exception("Invalid Network: {}".format(name))
    
    if type in ["networkv4", "networkv4v6"]:
        try:
            v4address = network["valuev4"]
        except KeyError:
            raise Exception("Invalid Network: {}".format(name))
        _set = Set("{}_v4".format(name), "inet", "ipv4_addr", table)
        address = ip_network(v4address)
        _set.add_member({ "prefix": {"addr": str(address.network_address), "len": address.prefixlen}})
        sets["{}_v4".format(name)] = _set
    
    if type in ["networkv6", "networkv4v6"]:
        try:
            v6address = network["valuev6"]
        except KeyError:
            raise Exception("Invalid Network: {}".format(name))
        _set = Set("{}_v6".format(name), "inet", "ipv6_addr", table)
        address = ip_network(v6address)
        _set.add_member({ "prefix": {"addr": str(address.network_address), "len": address.prefixlen}})
        sets["{}_v6".format(name)] = _set
    
def parse_service(service: dict, table: Table, sets: dict) -> None:
    try:
        name = service["name"]
        type = service["type"]
        port = service["value"]
    except KeyError:
        raise Exception("Invalid Service")
    
    if not type in ["tcp", "udp"]:
        raise Exception("Invalid Service: {}".format(name))
    
    _set = Set(name, "inet", "inet_service", table)
    _set.add_member(port)
    _set.protocol = type
    sets[name] = _set

def get_network_group_members(group: dict, objects: dict) -> tuple[list, list]:
    name = group["name"]
    type = group["type"]
    members = group["members"]

    _childrenv4 = []
    _childrenv6 = []
    for member in members:
        found = False
        try:
            _member = objects["hosts"][member]
            found = True
        except KeyError:
            pass
        try:
            _member = objects["networks"][member]
            found = True
        except KeyError:
            pass
        try:
            _member = objects["groups"][member]
            found = True
        except KeyError:
            pass
        if not found:
            raise Exception("Invalid group: {}".format(name))

        if _member["type"] in ["networkv4", "networkv4v6", "hostv4", "hostv4v6"]:
            _memberSet = sets["{}_v4".format(member)]
            for child in _memberSet.members:
                _childrenv4.append(child)
        if _member["type"] in ["networkv6", "networkv4v6", "hostv6", "hostv4v6"]:
            _memberSet = sets["{}_v6".format(member)]
            for child in _memberSet.members:
                _childrenv6.append(child)
        if _member["type"] == type:
            # Nested group
            v4, v6 = get_network_group_members(_member, objects)
            _childrenv4.extend(v4)
            _childrenv6.extend(v6)
    return _childrenv4, _childrenv6

def get_service_group_members(group: dict, objects: dict) -> tuple[list, list]:
    name = group["name"]
    type = group["type"]
    members = group["members"]
    
    _childrenTcp = []
    _childrenUdp = []

    for member in members:
        found = False
        try:
            _member = objects["services"][member]
            found = True
        except KeyError:
            pass
        try:
            _member = objects["groups"][member]
            found = True
        except KeyError:
            pass
        
        if not found:
            raise Exception("Invalid group: {}".format(name))
        if _member["type"] == "tcp":
            _memberSet = sets[member]
            for child in _memberSet.members:
                _childrenTcp.append(child)
            
        if _member["type"] == "udp":
            _memberSet = sets[member]
            for child in _memberSet.members:
                _childrenUdp.append(child)
        if _member["type"] == type:
            # Nested group
            tcp, udp = get_service_group_members(_member, objects)
            _childrenTcp.extend(tcp)
            _childrenUdp.extend(udp)
    return _childrenTcp, _childrenUdp

def parse_group(group: dict, table: Table, sets: dict, objects: dict) -> None:
    try:
        name = group["name"]
        type = group["type"]
        members = group["members"]
    except KeyError:
        raise Exception("Invalid Group")

    if not type in ["network", "service"]:
        raise Exception("Invalid Group: {}".format(name))
    
    if type == "network":
        # Network group
        _setv4 = None
        _setv6 = None
        membersv4, membersv6 = get_network_group_members(group, objects)
        if len(membersv4):
            _setv4 = Set("{}_v4".format(name), "inet", "ipv4_addr", table)
            for member in membersv4:
                _setv4.add_member(member)
            sets["{}_v4".format(name)] = _setv4
        if len(membersv6):
            _setv6 = Set("{}_v6".format(name), "inet", "ipv6_addr", table)
            for member in membersv6:
                _setv6.add_member(member)
            sets["{}_v6".format(name)] = _setv6

    if type == "service":
        # Service group
        _setUdp = None
        _setTcp = None
        membersTcp, membersUdp = get_service_group_members(group, objects)
        if len(membersTcp):
            _setTcp = Set("{}_tcp".format(name), "inet", "inet_service", table)
            for member in membersTcp:
                _setTcp.add_member(member)
            sets["{}_tcp".format(name)] = _setTcp
        if len(membersUdp):
            _setUdp = Set("{}_udp".format(name), "inet", "inet_service", table)
            for member in membersUdp:
                _setUdp.add_member(member)
            sets["{}_udp".format(name)] = _setUdp



if __name__ == "__main__":
    print("Starting", file=sys.stderr)
    jsn = json.load(open("rulebase.json", "r"))
    options = jsn["options"]
    objects = jsn["objects"]
    rulebase = jsn["rulebase"]

    defaultFilterChains = ["tcp", "udp", "icmp", "icmpv6", "icmp-local", "icmpv6-local", "input", "forward", "output"]

    rules = []
    tables = []
    sets = {}

    chains = {}
    tables = create_tables()
    chains = create_chains(options, tables[0])
    set_options(options, rules, chains)
    create_jumps(rules)
    for host in objects["hosts"].values():
        parse_host(host, tables[0], sets)
    for network in objects["networks"].values():
        parse_network(network, tables[0], sets)
    for service in objects["services"].values():
        parse_service(service, tables[0], sets)
    for group in objects["groups"].values():
        parse_group(group, tables[0], sets, objects)
    for rule in rulebase:
        for newRule in parse_rule(rule, chains, sets):
            rules.append(newRule)
    
    res = {"nftables": [{"flush": {"ruleset": None}}]}

    for table in tables:
        res["nftables"].append({"table": table})
    for set in sets.values():
        res["nftables"].append({"set": set})
    for chain in chains.values():
        res["nftables"].append({"chain": chain})
    for rule in rules:
        res["nftables"].append({"rule": rule})

    print(json.dumps(res))