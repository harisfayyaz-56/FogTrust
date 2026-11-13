"""Result submissions are rarer than heartbeats, so the limits are lower. Same two-bucket design."""

import os

from heartbeats.throttles import IPHeartbeatThrottle, NodeHeartbeatThrottle


class NodeResultThrottle(NodeHeartbeatThrottle):
    scope = "node_result"
    rate = os.environ.get("RESULT_NODE_RATE", "60/min")


class IPResultThrottle(IPHeartbeatThrottle):
    scope = "node_result_ip"
    rate = os.environ.get("RESULT_IP_RATE", "600/min")