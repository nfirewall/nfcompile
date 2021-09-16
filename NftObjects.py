from _helpers import validate_family, validate_op

class Action():
    pass

class AcceptAction(Action):
    def get(self):
        return {"accept": None}

class DropAction(Action):
    def get(self):
        return {"drop": None}   

class JumpAction(Action):
    _target = None
    def __init__(self, target) -> None:
        self._target = target

    def get(self):
        return {"jump": {"target": self._target.name}}

class Match(dict):

    def __init__(self, left, op, right):
        self.op = op
        self.left = left
        self.right = right

    @property
    def op(self) -> str:
        return self["op"]
    
    @op.setter
    def op(self, var: str) -> None:
        validate_op(var)
        self["op"] = var
    
    @property
    def left(self) -> dict:
        return self["left"]
    
    @left.setter
    def left(self, var: dict) -> None:
        self["left"] = var

    @property
    def right(self):
        return self["right"]
    
    @right.setter
    def right(self, var) -> None:
        self["right"] = var

class Rule(dict):
    _chain = None
    _action = None
    _matches = []
    _log = None

    def __init__(self, chain, id: str, log=True) -> None:
        self._chain = chain
        self._matches = []
        self._action = None
        self._log = None
        self["chain"] = chain.name
        self["table"] = chain.table.name
        self["family"] = chain.family
        self["expr"] = []
        if log:
            self._log = {"log": {"prefix": id, "group": 0}}
        self._refresh_expr()
    
    def _refresh_expr(self):
        self["expr"] = []
        if len(self._matches):
            for match in self._matches:
                self["expr"].append({"match": match})
        if self._action:
            self["expr"].append(self._action.get())
        if self._log:
            self["expr"].append(self._log)
    
    def add_match(self, match):
        matches = self.matches
        for _match in matches:
            if _match == match:
                return
        matches.append(match)
        self.matches = matches
    
    def delete_match(self, match):
        matches = self.matches
        _matches = []
        for _match in matches:
            if _match == match:
                continue
            _matches.append(_match)
        self.matches = matches


    @property
    def family(self) -> str:
        return self["family"]
    
    @family.setter
    def family(self, var: str) -> None:
        validate_family(var)
        self["family"] = var
    
    @property
    def action(self) -> Action:
        return self._action
    
    @action.setter 
    def action(self, var: Action) -> None:
        self._action = var
        self._refresh_expr()
        
    @property
    def matches(self) -> Match:
        return self._matches
    
    @matches.setter
    def matches(self, var: Match) -> None:
        self._matches = var
        self._refresh_expr()
        
    @property
    def chain(self):
        return self._chain
    
    @chain.setter
    def chain(self, var) -> None:
        self._chain = var
        self["chain"] = var.name
        self["table"] = var.table.name

class Chain(dict):
    _rules = []
    _table = None

    def __init__(self, family: str, name: str, table) -> None:
        self._table = table
        self._rules = []
        self["table"] = table.name
        self["family"] = family
        self["name"] = name
        self["policy"] = "accept"
        

    def add_rule(self, id: str) -> Rule:
        _rule = Rule(self, id)
        self._rules.append(_rule)
        return _rule


    @property
    def name(self) -> str:
        return self["name"]
    
    @name.setter
    def name(self, var: str) -> None:
        self["name"] = var
        
    @property
    def family(self) -> str:
        return self["family"]
    
    @family.setter
    def family(self, var: str) -> None:
        validate_family(var)
        self["family"] = var
    
    @property
    def table(self):
        return self._table
    
    @table.setter
    def table(self, var) -> None:
        self._table = var
    
    @property
    def type(self) -> str:
        try:
            return self["type"]
        except KeyError:
            return None
    @type.setter
    def type(self, var: str):
        if var not in ["filter", "route", "nat"]:
            raise Exception("Invalid type")
        self["type"] = var
    
    @property
    def hook(self) -> str:
        try:
            return self["hook"]
        except KeyError:
            return None
    @hook.setter
    def hook(self, var: str):
        if self.type != "filter":
            raise Exception("Hook only valid for filters")
        if var not in ["prerouting", "input", "forward", "output", "postrouting"]:
            raise Exception("Invalid hook")
        self["hook"] = var

    @property
    def priority(self) -> int:
        try:
            return self["prio"]
        except KeyError:
            return None
    @priority.setter
    def priority(self, var: int):
        self["prio"] = var

    @property
    def default(self) -> int:
        try:
            return self["policy"]
        except KeyError:
            return None
    @default.setter
    def default(self, var: int):
        if var not in ["accept", "drop", "reject"]:
            raise Exception("Invalid policy: {}".format(var))
        self["policy"] = var

class Table(dict):
    _chains = []
    

    def __init__(self, family: str, name: str) -> None:
        self["family"] = family
        self["name"] = name
        self._chains = []
    
    def add_chain(self, family: str, name: str) -> Chain:
        _chain = Chain(family, name, self)
        self._chains.append(_chain)
        return _chain
    
    @property
    def name(self) -> str:
        return self["name"]
    
    @name.setter
    def name(self, var: str) -> None:
        self["name"] = var
        
    @property
    def family(self) -> str:
        return self["family"]
    
    @family.setter
    def family(self, var: str) -> None:
        validate_family(var)
        self["family"] = var