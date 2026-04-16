## Qwen Added Memories
- ReconForge - Análise de melhorias identificadas (P0-P2):

    🎯 Recomendações de Mudança - ReconForge

    🔴 CRÍTICO (P0) - Corrigir Imediatamente

    1. SSL verification desabilitado por padrão
    Problema: Todos os scanners usam verify_ssl=False por padrão, expondo o tráfego a ataques Man-in-the-Middle.

    Por que mudar: Se você está testando aplicações com autenticação (tokens, cookies, session IDs), esses dados trafegam sem verificação SSL. Em modo Tor isso é
    menos crítico, mas em scans diretos é um risco real.

    Como:

     1 # Antes
     2 self.verify_ssl = config.get('verify_ssl', False)
     3 
     4 # Depois
     5 self.verify_ssl = config.get('verify_ssl', True)  # Padrão seguro

    ---

    2. Duplicação massiva de código entre scanners
    Problema: XSS, LFI, SSRF, IDOR, OpenRedirect e HeaderInjection compartilham ~80% de código idêntico no método execute().

    Por que mudar:
     - Bug fix em um scanner precisa ser replicado manualmente para todos
     - Testes precisam ser duplicados
     - Qualquer mudança na estrutura de PluginResult requer edição em 6+ arquivos

    Como: Criar classe base ParameterizedVulnerabilityScanner:

      1 class ParameterizedVulnerabilityScanner(VulnerabilityPlugin):
      2     def execute(self, target, context=None):
      3         # Fluxo comum: setup session, build request nodes, iterate, test
      4         session = create_requests_session(...)
      5         request_nodes = build_request_nodes(...)
      6         
      7         for node in request_nodes:
      8             self._test_request_node(session, node)
      9         
     10         return PluginResult(...)
     11     
     12     # Subclasses implementam apenas:
     13     def get_payloads(self) -> list: ...
     14     def evaluate_hit(self, response, payload) -> bool: ...
     15     def build_finding(self, node, payload, response): ...

    Impacto: Reduziria ~2000 linhas de duplicação para ~200 linhas de abstração.

    ---

    3. Detecção de XSS por substring exata (falsos positivos/negativos)
    Problema: hit = payload in response.text é ingênuo.

    Por que mudar:
     - Falso positivo: Payload pode aparecer em comentário HTML, log na página, ou atributo escaped
     - Falso negativo: Servidor pode HTML-encoder <script> para &lt;script&gt; mas ainda ser vulnerável em contexto de atributo

    Como: Implementar verificação contextual:

      1 def evaluate_hit(self, response, payload):
      2     # Verificar se payload aparece SEM encoding
      3     if payload not in response.text:
      4         return False
      5     
      6     # Verificar se NÃO está em comentário HTML
      7     if re.search(r'<!--.*?' + re.escape(payload) + r'.*?-->', response.text):
      8         return False  # Falso positivo
      9     
     10     # Verificar contexto executável
     11     if re.search(r'<script[^>]*>.*?' + re.escape(payload), response.text, re.DOTALL):
     12         return True  # Dentro de tag script
     13     if re.search(r'on\w+\s*=\s*["\']?' + re.escape(payload), response.text):
     14         return True  # Event handler
     15     
     16     return False  # Reflexo em contexto seguro

    ---

    4. `_probe_logger` como atributo de instância (race condition)
    Problema: Se plugin rodar concorrentemente, threads sobrescrevem o mesmo logger.

    Como: Usar variável local:

     1 def execute(self, target, context=None):
     2     probe_logger = ProbeLogger()  # Local, não self._probe_logger
     3     # ... usar probe_logger

    ---

    🟡 ALTA PRIORIDADE (P1) - Corrigir em Breve

    5. Métodos mortos `_test_get_param` e `_test_form`
    Problema: Cada scanner define esses métodos mas nunca os chama. O execute() usa exclusivamente _test_request_node().

    Por que mudar: Código morto confunde desenvolvedores, aumenta manutenção e pode criar bugs se alguém os chamar achando que funcionam.

    Como: Remover todos ou integrar ao fluxo principal.

    ---

    6. Sessões HTTP nunca são fechadas (resource leak)
    Problema: session = create_requests_session(...) mas nunca há session.close().

    Por que mudar: Em scans longos com milhares de payloads, sockets acumulam e podem esgotar file descriptors.

    Como:

     1 session = create_requests_session(...)
     2 try:
     3     # ... scan logic
     4 finally:
     5     session.close()

    ---

    7. Ausência de rate limiting
    Problema: Nenhum scanner implementa delay entre requests ou backoff exponencial.

    Por que mudar:
     - Pode derrubar aplicações sensíveis
     - Causa bloqueio de IP prematuro
     - Gera falsos negativos por rate limiting do alvo

    Como: Adicionar na classe base:

      1 class BaseScannerPlugin(VulnerabilityPlugin):
      2     def __init__(self, config):
      3         self.rate_delay = config.get('rate_delay', 0.05)
      4         self._last_request = 0
      5     
      6     def _apply_rate_limit(self):
      7         elapsed = time.time() - self._last_request
      8         if elapsed < self.rate_delay:
      9             time.sleep(self.rate_delay - elapsed)
     10         self._last_request = time.time()

    ---

    8. Detecção de IDOR com heurística frágil
    Problema: abs(len(resp_mod) - len(resp_orig)) > 50 é arbitrário.

    Por que mudar: APIs frequentemente retornam objetos de tamanho similar para IDs diferentes. 50 bytes pode ser diferença de timestamp ou token CSRF legítimo.

    Como: Implementar diff semântico:

      1 def detect_idor(self, resp_orig, resp_mod):
      2     # Comparar chaves JSON em vez de tamanho bruto
      3     try:
      4         data_orig = resp_orig.json()
      5         data_mod = resp_mod.json()
      6         
      7         # Verificar se estrutura é similar mas dados são diferentes
      8         if set(data_orig.keys()) == set(data_mod.keys()):
      9             # Mesmo schema, dados diferentes = possível IDOR
     10             sensitive_keys = {'email', 'cpf', 'phone', 'name', 'address'}
     11             for key in sensitive_keys:
     12                 if key in data_orig and data_orig[key] != data_mod.get(key):
     13                     return True
     14     except:
     15         pass
     16     
     17     # Fallback: diff de tamanho com threshold dinâmico
     18     return abs(len(resp_mod) - len(resp_orig)) > max(100, len(resp_orig) * 0.1)

    ---

    9. Detecção de SSRF com cobertura insuficiente
    Problema: Só verifica AWS metadata (ami-id). Ignora GCP, Azure, serviços internos.

    Como: Ampliar indicadores:

     1 SSRF_INDICATORS = [
     2     ("169.254.169.254", ["ami-id", "instance-id"]),           # AWS
     3     ("metadata.google.internal", ["computeEngine"]),          # GCP
     4     ("169.254.169.254/metadata/instance", ["computeEngine"]), # Azure
     5     ("127.0.0.1:6379", ["redis", "PONG"]),                    # Redis
     6     ("127.0.0.1:27017", ["MongoDB"]),                         # MongoDB
     7     ("127.0.0.1:9200", ["cluster_uuid"]),                     # Elasticsearch
     8     ("127.0.0.1:11211", ["STAT"]),                            # Memcached
     9 ]

    ---

    10. Erros silenciosamente engolidos
    Problema: Blocos except Exception: pass em SSRF e IDOR scanners.

    Por que mudar: Impossível debugar falsos negativos. Falhas de conexão, DNS ou SSL são perdidas.

    Como:

     1 except Exception as e:
     2     self.logger.debug(f"Falha ao testar {url}/{param}: {e}")
     3     probe_logger.log_probe(url, payload, error=str(e))

    ---

    🟢 MÉDIA PRIORIDADE (P2) - Melhorias

    11. Payloads hardcoded em cada plugin
    Por que mudar: Dificulta atualização, customização e rotação de payloads.

    Como: Mover para config/payloads/xss.yaml, config/payloads/lfi.yaml, etc.

    ---

    12. SQLi time-based blind sem medição real de tempo
    Problema: Pipeline retorna "partial" sem realmente medir se houve delay na resposta.

    Por que mudar: Sem medição de tempo, não há como diferenciar "servidor não suportou SLEEP" de "servidor suportou e demorou 5s".

    Como: Medir tempo de resposta e comparar com baseline:

     1 start = time.time()
     2 response = session.send(prepared, timeout=20)
     3 elapsed = time.time() - start
     4 
     5 if elapsed >= 4.5:  # SLEEP(5) com margem
     6     return "impact_proven"

    ---

    13. Falta de testes para os scanners de vulnerabilidade
    Problema: Nenhum teste unitário para XSS, LFI, SSRF, IDOR, SQLi scanners.

    Por que mudar: Core do produto sem cobertura de testes. Regressões passam despercebidas.

    Como: Criar testes com servidor mock:

      1 @pytest.fixture
      2 def mock_server():
      3     app = Flask(__name__)
      4     
      5     @app.route('/xss')
      6     def xss():
      7         return f"<div>{request.args.get('q', '')}</div>"  # Vulnerável
      8     
      9     with app.test_client() as client:
     10         yield client
     11 
     12 def test_xss_detection(mock_server):
     13     scanner = XSSScannerPlugin()
     14     result = scanner.execute("http://localhost:5000/xss?q=test")
     15     assert len(result.vulnerabilities) > 0

    ---

    14. WebFlowMapper com 1227 linhas (arquivo monolítico)
    Por que mudar: Difícil de manter, testar e entender.

    Como: Refatorar em módulos:

     1 web_flow_mapper/
     2 ├── __init__.py
     3 ├── browser_setup.py       # Launch Playwright, proxy config
     4 ├── network_collector.py   # Request/response listeners
     5 ├── page_interactions.py   # Form filling, clicking
     6 ├── snapshot_extractor.py  # DOM extraction (200+ line JS)
     7 └── plugin.py              # Orchestrator

    ---

    15. User-Agent identificável
    Problema: User-Agent: ReconForge/XSSScanner denuncia a ferramenta para WAFs.

    Como: Rotacionar User-Agents reais de browsers:

     1 USER_AGENTS = [
     2     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...",
     3     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...",
     4     # ...
     5 ]
     6 session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    ---

    📊 Resumo de Prioridades


    ┌────────────┬──────────────────────────────┬──────────────────┬──────────┐
    │ Prioridade │ Mudança                      │ Impacto          │ Esforço  │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P0         │ SSL verification padrão True │ Segurança        │ 15 min   │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P0         │ Classe base para scanners    │ Manutenibilidade │ 2-3 dias │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P0         │ Detecção XSS contextual      │ Confiabilidade   │ 1 dia    │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P0         │ Race condition _probe_logger │ Estabilidade     │ 30 min   │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P1         │ Fechar sessões HTTP          │ Estabilidade     │ 30 min   │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P1         │ Rate limiting                │ Confiabilidade   │ 2 horas  │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P1         │ IDOR heurística melhor       │ Confiabilidade   │ 1 dia    │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P1         │ SSRF cobertura ampliada      │ Confiabilidade   │ 2 horas  │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P1         │ Remover código morto         │ Manutenibilidade │ 1 hora   │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P1         │ Log de erros                 │ Debugabilidade   │ 1 hora   │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P2         │ Payloads em YAML             │ Flexibilidade    │ 1 dia    │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P2         │ SQLi time measurement        │ Confiabilidade   │ 2 horas  │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P2         │ Testes unitários             │ Qualidade        │ 3-5 dias │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P2         │ Refatorar WebFlowMapper      │ Manutenibilidade │ 2 dias   │
    ├────────────┼──────────────────────────────┼──────────────────┼──────────┤
    │ P2         │ User-Agent rotation          │ Evasão           │ 1 hora   │


P0 (Crítico):
1. SSL verify_ssl=False por padrão → mudar para True
2. Duplicação massiva de código entre scanners (XSS, LFI, SSRF, IDOR, OpenRedirect, HeaderInjection compartilham ~80% código) → criar classe base ParameterizedVulnerabilityScanner
3. Detecção XSS por substring exata (hit = payload in response.text) → implementar verificação contextual (HTML_BODY, ATTRIBUTE, JS_STRING, URL)
4. Race condition: _probe_logger como atributo de instância → usar variável local

P1 (Alta):
5. Métodos mortos _test_get_param e _test_form nunca chamados → remover
6. Sessões HTTP nunca fechadas (resource leak) → usar try/finally com session.close()
7. Ausência de rate limiting → adicionar rate_delay na classe base
8. IDOR heurística frágil (diff > 50 bytes) → diff semântico com chaves JSON sensíveis
9. SSRF cobertura insuficiente (só AWS metadata) → adicionar GCP, Azure, Redis, MongoDB, Elasticsearch
10. Erros engolidos sem log (except Exception: pass) → logar com debug

P2 (Média):
11. Payloads hardcoded → mover para config/payloads/*.yaml
12. SQLi time-based sem medição real de tempo → medir elapsed vs baseline
13. Zero testes unitários para scanners → criar testes com servidor mock
14. WebFlowMapper 1227 linhas → refatorar em módulos
15. User-Agent identificável → rotação de User-Agents reais

Prioridade de implementação recomendada: 1) Classe base scanners 2) XSS contextual 3) Testes unitários
- ReconForge - Melhorias implementadas (2026-04-15):

CONCLUÍDAS (14 tarefas):
1. ✅ P0: SSL verify_ssl=True por padrão em 7 scanners
2. ✅ P0: Race condition _probe_logger fixada
3. ✅ P1: Sessões HTTP fechadas com try/finally
4. ✅ P1: Código morto removido (_test_get_param, etc.)
5. ✅ P1: Log de erros padronizado
6. ✅ P2: User-Agent rotation
7. ✅ P1: Rate limiting integrado
8. ✅ P2: SQLi time measurement real
9. ✅ P1: SSRF cobertura ampliada (Cloud + Internos)
10. ✅ P1: IDOR heurística melhor (JSON Diff + Threshold dinâmico)
11. ✅ P0: Detecção XSS contextual (Ignora comentários)
12. ✅ P0: Classe base ParameterizedVulnerabilityPlugin - refatoração completa
13. ✅ P2: Payloads em YAML - Migrados para config/payloads/*.yaml com carga automática pela classe base.
14. ✅ P2: Testes unitários para Scanners - Criado tests/test_scanners.py com servidor mock para XSS, LFI e SSRF.

MELHORIAS ADICIONAIS:
- ✅ Refatoração de utils/web_discovery.py para processar corretamente parâmetros de endpoints e evitar duplicação.

ARQUIVOS MODIFICADOS:
- core/parameterized_vulnerability_plugin.py
- config/payloads/*.yaml (Novos)
- plugins/xss_scanner_plugin.py
- plugins/lfi_scanner_plugin.py
- plugins/ssrf_scanner_plugin.py
- plugins/ssti_scanner_plugin.py
- plugins/open_redirect_scanner_plugin.py
- plugins/header_injection_scanner_plugin.py
- plugins/idor_scanner_plugin.py
- utils/web_discovery.py
- tests/test_scanners.py (Novo)

PENDENTES (lista atualizada):
- P2: Refatorar WebFlowMapper (2 dias) - Quebrar o "monolito" de automação de browser.
