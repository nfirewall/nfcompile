from Exceptions import InvalidFamilyException, InvalidOperationException

families = ["ip", "ip6", "inet"]
ops = ["==", "in"]

def validate_family(family):
    if not family in families:
        raise InvalidFamilyException("Invalid family: {}".format(family))

def validate_op(op):
    if not op in ops:
        raise InvalidOperationException("Invalid Operation: {}".format(op))


def default(dict, key, default):
    try:
        return dict[key]
    except KeyError:
        return default