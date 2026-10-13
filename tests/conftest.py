import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# test_tor_plugins.py é um script manual de validação de Tor (tem seu próprio
# main() e exige um daemon Tor ativo em 127.0.0.1:9050). Suas funções test_*
# recebem argumentos e são orquestradas pelo main(), não são testes pytest —
# por isso é excluído da coleta automática. Rode-o com:
#     python tests/test_tor_plugins.py
collect_ignore = ["test_tor_plugins.py"]
