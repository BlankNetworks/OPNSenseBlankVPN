"""Read only a Clash proxy list. YAML aliases, arbitrary tags and duplicate keys are rejected."""

import json
import sys

try:
    import yaml
except ImportError:
    raise SystemExit(2)


class ProxyLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self.depth = 0
        self.nodes = 0

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent) or self.depth >= 24 or self.nodes >= 16000:
            raise ValueError("Unsupported YAML alias or structure")
        self.depth += 1
        self.nodes += 1
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node, deep=False):
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        if any(not isinstance(key, str) for key in keys) or len(set(keys)) != len(keys):
            raise ValueError("Invalid or duplicate YAML key")
        return super().construct_mapping(node, deep=deep)


try:
    data = sys.stdin.buffer.read(2_097_153)
    if len(data) > 2_097_152:
        raise ValueError("Oversized YAML document")
    document = yaml.load(data, Loader=ProxyLoader)
    if not isinstance(document, dict) or not isinstance(document.get("proxies"), list):
        raise ValueError("Expected a proxy list")
    output = json.dumps({"proxies": document["proxies"]}, allow_nan=False)
    if len(output) > 2_097_152:
        raise ValueError("Oversized proxy list")
    sys.stdout.write(output)
except (ValueError, TypeError, yaml.YAMLError):
    raise SystemExit(1)
