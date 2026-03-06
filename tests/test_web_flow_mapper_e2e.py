import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


playwright = pytest.importorskip("playwright")

from plugins.web_flow_mapper import WebFlowMapperPlugin


class _FlowHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/":
            body = """
            <html><body>
              <a href="/login">Efetuar Login</a>
            </body></html>
            """
        elif self.path == "/login":
            body = """
            <html><body>
              <form id="login" method="post" action="/login/post">
                <input name="login" type="text">
                <input name="senha" type="password">
                <input type="submit" value="Entrar">
              </form>
              <script>
                document.getElementById('login').addEventListener('submit', function (event) {
                  event.preventDefault();
                  const form = event.target;
                  const login = form.querySelector('[name=login]').value;
                  const senha = form.querySelector('[name=senha]').value;
                  window.location.href = form.action + '?login=' + encodeURIComponent(login) + '&senha=' + encodeURIComponent(senha);
                });
              </script>
            </body></html>
            """
        elif self.path.startswith("/login/post"):
            body = "<html><body>Login invalido</body></html>"
        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):  # noqa: A003
        return


@pytest.fixture()
def flow_server():
    server = HTTPServer(("127.0.0.1", 0), _FlowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_web_flow_mapper_captures_observed_get_route(flow_server):
    plugin = WebFlowMapperPlugin()
    plugin.config.update({"headless": True, "max_depth": 1, "max_pages": 5, "max_actions_per_page": 5})

    result = plugin.execute(flow_server, {"original_target": flow_server})

    assert result.success is True
    request_nodes = result.data["request_nodes"]
    assert any(node["url"].startswith(f"{flow_server}/login/post?") and node["method"] == "GET" for node in request_nodes)
