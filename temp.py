import json

with open("tmp2.json", "w") as fh:
    fh.write(json.dumps(json.load(open("tmp.json", "r")), indent=4))