#!/usr/bin/env python3
"""
Scanner de Diretórios em Python
Substituto para Feroxbuster/Dirbuster - Scanner de diretórios eficiente em Python puro
"""

import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Set
from datetime import datetime
from urllib.parse import urljoin, urlparse
import os

from utils.logger import obter_logger


class ScannerDiretoriosPython:
    """Scanner de diretórios eficiente em Python puro"""

    def __init__(self):
        self.logger = obter_logger("DirScanner")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.timeout = 5
        self.max_workers = 20
        
    def executar_scan(self, alvo):
        """
        Método compatível com o Orquestrador para executar o scan de diretórios
        Args:
            alvo (str): URL ou IP do alvo
        Returns:
            dict: Resultado do scan de diretórios
        """
        self.logger.info(f"Iniciando scan de diretórios para: {alvo}")
        
        try:
            # Garantir que o alvo tenha protocolo
            if not alvo.startswith(('http://', 'https://')):
                url = f"http://{alvo}"
            else:
                url = alvo
                
            inicio = time.time()
            resultados = self.scan_completo(url, testar_extensoes=True)
            tempo_execucao = time.time() - inicio
            
            # Formatar resultado para compatibilidade com orquestrador
            return {
                'sucesso': True,
                'alvo': alvo,
                'urls_encontradas': resultados.get('urls_encontradas', []),
                'total_testado': resultados.get('total_testado', 0),
                'tempo_execucao': tempo_execucao,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Erro no scan de diretórios: {str(e)}")
            return {
                'sucesso': False,
                'alvo': alvo,
                'erro': str(e),
                'timestamp': datetime.now().isoformat()
            }

        # Wordlists de diretórios
        self.diretorios_comuns = [
            'admin', 'administrator', 'login', 'logon', 'signin', 'auth',
            'authentication', 'dashboard', 'panel', 'control', 'manage',
            'management', 'adminpanel', 'cpanel', 'plesk', 'webmail',
            'mail', 'email', 'smtp', 'pop', 'imap', 'ftp', 'ssh',
            'remote', 'vpn', 'ssl', 'secure', 'private', 'internal',
            'backup', 'backups', 'old', 'new', 'temp', 'tmp', 'cache',
            'test', 'testing', 'demo', 'dev', 'development', 'staging',
            'beta', 'alpha', 'sandbox', 'lab', 'qa', 'quality',
            'api', 'rest', 'soap', 'xml', 'json', 'rss', 'feed',
            'upload', 'uploads', 'download', 'downloads', 'files',
            'images', 'img', 'pics', 'photos', 'assets', 'static',
            'css', 'js', 'javascript', 'scripts', 'fonts', 'icons',
            'docs', 'documentation', 'help', 'support', 'faq',
            'blog', 'news', 'articles', 'posts', 'archive', 'archives',
            'search', 'find', 'query', 'status', 'info', 'about',
            'contact', 'contact-us', 'privacy', 'terms', 'legal',
            'sitemap', 'robots', 'rss', 'atom', 'feed', 'xmlrpc',
            'wp-admin', 'wp-content', 'wp-includes', 'wp-json',
            'administrator', 'joomla', 'drupal', 'magento', 'prestashop',
            'phpmyadmin', 'pma', 'mysql', 'database', 'db', 'sql',
            'config', 'configuration', 'settings', 'setup', 'install',
            'update', 'upgrade', 'patch', 'hotfix', 'maintenance',
            'server-status', 'server-info', 'phpinfo', 'test',
            '.git', '.svn', '.DS_Store', '.htaccess', '.htpasswd',
            'web.config', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'readme', 'changelog', 'license', 'version', 'build'
        ]

        # Extensões de arquivos para testar
        self.extensoes_arquivos = [
            '.txt', '.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.js',
            '.css', '.xml', '.json', '.sql', '.bak', '.old', '.zip', '.rar',
            '.tar', '.gz', '.7z', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.ppt', '.pptx', '.log', '.conf', '.config', '.ini', '.env',
            '.yml', '.yaml', '.toml', '.md', '.markdown', '.rst'
        ]

    def scan_completo(self, url_base: str, wordlist_customizada: Optional[List[str]] = None,
                      testar_extensoes: bool = True, recursivo: bool = False,
                      max_profundidade: int = 2) -> Dict:
        """
        Executa scan completo de diretórios

        Args:
            url_base: URL base para scan
            wordlist_customizada: Lista customizada de diretórios
            testar_extensoes: Testar extensões de arquivos
            recursivo: Scan recursivo
            max_profundidade: Profundidade máxima para scan recursivo

        Returns:
            Dict com resultados do scan
        """
        self.logger.info(f"🔍 Iniciando scan de diretórios: {url_base}")

        inicio = time.time()

        try:
            # Normalizar URL
            if not url_base.startswith(('http://', 'https://')):
                url_base = f'https://{url_base}'

            # Remover barra final
            url_base = url_base.rstrip('/')

            # Preparar wordlist
            if wordlist_customizada:
                diretorios_testar = wordlist_customizada
            else:
                diretorios_testar = self.diretorios_comuns.copy()

            # Adicionar extensões se solicitado
            if testar_extensoes:
                diretorios_com_extensao = []
                for diretorio in diretorios_testar:
                    diretorios_com_extensao.append(diretorio)
                    for ext in self.extensoes_arquivos:
                        diretorios_com_extensao.append(f"{diretorio}{ext}")
                diretorios_testar = diretorios_com_extensao

            self.logger.info(f"📋 Testando {len(diretorios_testar)} caminhos...")

            # Executar scan
            resultados = self._scan_diretorios(url_base, diretorios_testar)

            # Scan recursivo se solicitado
            if recursivo and resultados['diretorios_encontrados']:
                self.logger.info("🔄 Executando scan recursivo...")
                resultados_recursivos = self._scan_recursivo(
                    url_base, resultados['diretorios_encontrados'],
                    max_profundidade, testar_extensoes
                )
                # Mesclar resultados
                for key in ['urls_encontradas', 'diretorios_encontrados', 'arquivos_encontrados']:
                    if key in resultados_recursivos:
                        resultados[key].extend(resultados_recursivos[key])

            # Analisar resultados
            self._analisar_resultados(resultados)

            duracao = time.time() - inicio
            resultados['duracao_segundos'] = round(duracao, 2)
            resultados['total_testado'] = len(diretorios_testar)

            self.logger.info(f"✅ Scan concluído: {len(resultados['urls_encontradas'])} caminhos encontrados")
            return resultados

        except Exception as e:
            self.logger.error(f"❌ Erro no scan: {e}")
            return {
                'url_base': url_base,
                'erro': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def _scan_diretorios(self, url_base: str, caminhos: List[str]) -> Dict:
        """Executa scan de diretórios usando múltiplas threads"""
        resultados = {
            'url_base': url_base,
            'urls_encontradas': [],
            'diretorios_encontrados': [],
            'arquivos_encontrados': [],
            'respostas_interessantes': [],
            'timestamp': datetime.now().isoformat()
        }

        lock = threading.Lock()

        def testar_caminho(caminho: str):
            test_url = urljoin(url_base + '/', caminho)

            try:
                response = self.session.get(test_url, timeout=self.timeout,
                                          verify=False, allow_redirects=True)

                # Verificar se é uma resposta interessante
                if self._is_resposta_interessante(response):
                    info = {
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_type': response.headers.get('content-type', ''),
                        'titulo': self._extrair_titulo(response.text) if response.text else None,
                        'servidor': response.headers.get('server', ''),
                        'caminho': caminho
                    }

                    with lock:
                        resultados['urls_encontradas'].append(info)

                        # Categorizar
                        if response.status_code == 200:
                            if '.' in caminho:
                                resultados['arquivos_encontrados'].append(info)
                            else:
                                resultados['diretorios_encontrados'].append(info)

                        # Respostas interessantes (403, 401, etc.)
                        if response.status_code in [401, 403, 500]:
                            resultados['respostas_interessantes'].append(info)

                    self.logger.debug(f"✅ Encontrado: {test_url} ({response.status_code})")

            except Exception as e:
                self.logger.debug(f"Erro ao testar {test_url}: {e}")

        # Executar em paralelo
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(testar_caminho, caminho) for caminho in caminhos]

            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass

        return resultados

    def _is_resposta_interessante(self, response: requests.Response) -> bool:
        """Verifica se a resposta HTTP é interessante"""
        # Status codes interessantes
        status_interessantes = [200, 201, 301, 302, 401, 403, 500]

        if response.status_code not in status_interessantes:
            return False

        # Verificar tamanho do conteúdo (evitar páginas muito grandes)
        if len(response.content) > 10 * 1024 * 1024:  # 10MB
            return False

        # Verificar se não é uma página de erro padrão
        if response.status_code == 200:
            content_lower = response.text.lower()
            # Evitar páginas padrão de erro
            if any(error in content_lower for error in [
                '404 not found', 'page not found', 'error 404',
                '403 forbidden', 'access denied', 'forbidden'
            ]):
                return False

        return True

    def _extrair_titulo(self, html: str) -> Optional[str]:
        """Extrai título da página HTML"""
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    def _scan_recursivo(self, url_base: str, diretorios_base: List[Dict],
                       max_profundidade: int, testar_extensoes: bool) -> Dict:
        """Executa scan recursivo nos diretórios encontrados"""
        resultados_recursivos = {
            'urls_encontradas': [],
            'diretorios_encontrados': [],
            'arquivos_encontrados': []
        }

        # Palavras para scan recursivo (mais específicas)
        palavras_recursivas = [
            'admin', 'config', 'backup', 'upload', 'download', 'files',
            'images', 'css', 'js', 'assets', 'private', 'secure', 'tmp'
        ]

        for profundidade in range(1, max_profundidade + 1):
            self.logger.debug(f"🔄 Profundidade {profundidade}/{max_profundidade}")

            novos_diretorios = []

            for dir_info in diretorios_base:
                base_path = dir_info['caminho']

                for palavra in palavras_recursivas:
                    sub_path = f"{base_path}/{palavra}"

                    # Testar diretório
                    test_url = urljoin(url_base + '/', sub_path)
                    try:
                        response = self.session.get(test_url, timeout=self.timeout,
                                                  verify=False, allow_redirects=True)

                        if self._is_resposta_interessante(response):
                            info = {
                                'url': test_url,
                                'status_code': response.status_code,
                                'content_length': len(response.content),
                                'content_type': response.headers.get('content-type', ''),
                                'titulo': self._extrair_titulo(response.text) if response.text else None,
                                'servidor': response.headers.get('server', ''),
                                'caminho': sub_path,
                                'profundidade': profundidade
                            }

                            resultados_recursivos['urls_encontradas'].append(info)

                            if response.status_code == 200:
                                if '.' in sub_path:
                                    resultados_recursivos['arquivos_encontrados'].append(info)
                                else:
                                    resultados_recursivos['diretorios_encontrados'].append(info)
                                    novos_diretorios.append(info)

                    except:
                        continue

            # Atualizar para próxima profundidade
            diretorios_base = novos_diretorios

            if not novos_diretorios:
                break

        return resultados_recursivos

    def _analisar_resultados(self, resultados: Dict):
        """Analisa resultados do scan para insights"""
        urls = resultados['urls_encontradas']

        # Estatísticas
        status_codes = {}
        content_types = {}
        servidores = {}

        for url_info in urls:
            # Contar status codes
            status = url_info['status_code']
            status_codes[status] = status_codes.get(status, 0) + 1

            # Contar content types
            ct = url_info.get('content_type', '').split(';')[0]
            if ct:
                content_types[ct] = content_types.get(ct, 0) + 1

            # Contar servidores
            server = url_info.get('servidor', '')
            if server:
                servidores[server] = servidores.get(server, 0) + 1

        resultados['estatisticas'] = {
            'status_codes': status_codes,
            'content_types': content_types,
            'servidores': servidores,
            'total_urls': len(urls),
            'total_diretorios': len(resultados['diretorios_encontrados']),
            'total_arquivos': len(resultados['arquivos_encontrados']),
            'total_interessantes': len(resultados['respostas_interessantes'])
        }

    def salvar_resultados(self, resultado: Dict, formato: str = 'json', arquivo: str = None):
        """Salva resultados do scan em arquivo"""
        if not arquivo:
            parsed_url = urlparse(resultado['url_base'])
            dominio = parsed_url.netloc.replace('.', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            arquivo = f"diretorios_{dominio}_{timestamp}.{formato}"

        if formato == 'json':
            with open(arquivo, 'w', encoding='utf-8') as f:
                import json
                json.dump(resultado, f, indent=2, ensure_ascii=False)

        elif formato == 'txt':
            with open(arquivo, 'w', encoding='utf-8') as f:
                f.write(f"Scan de Diretórios - {resultado['url_base']}\\n")
                f.write(f"Total testado: {resultado.get('total_testado', 0)}\\n")
                f.write(f"Encontrados: {len(resultado['urls_encontradas'])}\\n")
                f.write(f"Data: {resultado['timestamp']}\\n\\n")

                if resultado['urls_encontradas']:
                    f.write("URLs ENCONTRADAS:\\n")
                    for url_info in resultado['urls_encontradas']:
                        status_emoji = "✅" if url_info['status_code'] == 200 else "⚠️" if url_info['status_code'] in [401, 403] else "ℹ️"
                        f.write(f"{status_emoji} {url_info['status_code']} - {url_info['url']}\\n")
                        if url_info.get('titulo'):
                            f.write(f"    Título: {url_info['titulo']}\\n")
                        f.write("\\n")

        self.logger.info(f"💾 Resultados salvos em: {arquivo}")


# Funções de compatibilidade
def scan_diretorios(url: str) -> Dict:
    """Função de compatibilidade para scan básico"""
    scanner = ScannerDiretoriosPython()
    return scanner.scan_completo(url)

def scan_diretorios_recursivo(url: str, profundidade: int = 2) -> Dict:
    """Função de compatibilidade para scan recursivo"""
    scanner = ScannerDiretoriosPython()
    return scanner.scan_completo(url, recursivo=True, max_profundidade=profundidade)


if __name__ == "__main__":
    # Teste do scanner
    scanner = ScannerDiretoriosPython()

    # Teste com URL de exemplo
    url_teste = "https://httpbin.org"

    print(f"🔍 Testando scan de diretórios em: {url_teste}")
    resultado = scanner.scan_completo(url_teste, testar_extensoes=False)

    if 'erro' not in resultado:
        print(f"✅ Scan concluído: {len(resultado['urls_encontradas'])} caminhos encontrados")
        print("\\n📋 Alguns resultados:")

        for url_info in resultado['urls_encontradas'][:10]:
            status_emoji = "✅" if url_info['status_code'] == 200 else "⚠️" if url_info['status_code'] in [401, 403] else "ℹ️"
            print(f"  {status_emoji} {url_info['status_code']} - {url_info['caminho']}")
    else:
        print(f"❌ Erro: {resultado['erro']}")
