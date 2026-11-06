"""
A throwaway local broker for end-to-end tests (not a test file). It calls the engine exactly the
way the Django views will: raw body first, then verify_heartbeat / verify_result_request.
"""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from fogtrust_crypto import codes
from fogtrust_crypto.heartbeat import verify_heartbeat
from fogtrust_crypto.node_auth import NodeInfo
from fogtrust_crypto.replay import InMemoryReplayStore
from fogtrust_crypto.results import verify_result_request

HTTP_STATUS = {
    codes.NODE_REVOKED: 403,
    codes.RESULT_NOT_ASSIGNED: 403,
    codes.RESULT_INTEGRITY_FAILED: 422,
    codes.PAYLOAD_TOO_LARGE: 413,
    codes.VALIDATION_ERROR: 400,
    codes.MALFORMED_REQUEST: 400,
    codes.HEARTBEAT_REPLAYED: 409,
    codes.HEARTBEAT_COUNTER_REGRESSED: 409,
}
RESULT_ROUTE = re.compile(r"^/api/v1/node-api/tasks/([0-9a-f-]{36})/result/$")


class StubBroker:
    def __init__(self, server_private_key):
        self.nodes = {}  # node_id -> NodeInfo
        self.assignments = {}  # task_id -> node_id
        self.store = InMemoryReplayStore()
        self.decisions = []
        self.plaintexts = {}  # task_id -> decrypted bytes
        broker = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                headers = dict(self.headers.items())
                match = RESULT_ROUTE.match(self.path)
                if self.path == "/api/v1/node-api/heartbeat/":
                    result = verify_heartbeat(headers, "POST", self.path, body, broker.nodes.get, broker.store)
                elif match:
                    task_id = match.group(1)
                    outcome = verify_result_request(
                        headers, "POST", self.path, body, broker.nodes.get, broker.store,
                        server_private_key, task_id, broker.assignments.get(task_id),
                    )
                    result = outcome.result
                    if outcome.accepted:
                        broker.plaintexts[task_id] = outcome.plaintext
                else:
                    self._reply(404, {"error": {"code": "NOT_FOUND"}})
                    return
                broker.decisions.append(result)
                if result.accepted:
                    self._reply(200, {"accepted": True})
                else:
                    self._reply(HTTP_STATUS.get(result.reason_code, 401), {"error": {"code": result.reason_code}})

            def _reply(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def enroll(self, node_id, public_key_b64, status="active"):
        self.nodes[node_id] = NodeInfo(public_key_b64, status)

    def close(self):
        self.server.shutdown()
        self.server.server_close()