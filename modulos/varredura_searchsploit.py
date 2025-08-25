#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de varredura SearchSploit
Busca exploits usando SearchSploit
"""

import os
import subprocess
import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
import re

from core.configuracao import obter_config

class VarreduraSearchSploit:
    """Classe para executar buscas SearchSploit"""
    
    def __init__(self):
        """Inicializa o módulo de varredura SearchSploit"""
        self.logger = logging.getLogger(__name__)
        self.binario_searchsploit = obter_config('searchsploit.binario', 'searchsploit')
        self.timeout_padrao = obter_config('searchsploit.timeout_padrao', 60)
        self.opcoes_padrao = obter_config('searchsploit.opcoes_padrao', [])
        
        # Verificar se o SearchSploit está disponível
        self.verificar_searchsploit()
    
    def verificar_searchsploit(self) -> bool:
        """
        Verifica se o SearchSploit está instalado e acessível
        Returns:
            bool: True se SearchSploit está disponível, False caso contrário
        """
        try:
            resultado = subprocess.run(
                [self.binario_searchsploit, '--help'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if resultado.returncode == 0:
                self.logger.info("SearchSploit encontrado")
                return True
            else:
                self.logger.error("SearchSploit não encontrado ou erro na execução")
                return False
                
        except FileNotFoundError:
            self.logger.error(f"Binário SearchSploit não encontrado: {self.binario_searchsploit}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout ao verificar SearchSploit")
            return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar SearchSploit: {str(e)}")
            return False
    
    def buscar_exploits(self, termo: str, exato: bool = False) -> Dict[str, Any]:
        """
        Busca exploits por termo
        Args:
            termo (str): Termo de busca
            exato (bool): Busca exata
        Returns:
            Dict[str, Any]: Resultados da busca
        """
        comando = [self.binario_searchsploit, '--json']
        
        if exato:
            comando.append('--exact')
        
        comando.append(termo)
        
        return self._executar_busca(comando, "buscar_exploits")
    
    def buscar_por_servico(self, servico: str, versao: Optional[str] = None) -> Dict[str, Any]:
        """
        Busca exploits por serviço e versão
        Args:
            servico (str): Nome do serviço
            versao (str): Versão específica
        Returns:
            Dict[str, Any]: Resultados da busca
        """
        termo_busca = servico
        if versao:
            termo_busca += f" {versao}"
        
        comando = [self.binario_searchsploit, '--json', termo_busca]
        
        return self._executar_busca(comando, "buscar_por_servico")
    
    def buscar_por_plataforma(self, termo: str, plataforma: str) -> Dict[str, Any]:
        """
        Busca exploits por plataforma específica
        Args:
            termo (str): Termo de busca
            plataforma (str): Plataforma (linux, windows, etc.)
        Returns:
            Dict[str, Any]: Resultados da busca
        """
        comando = [
            self.binario_searchsploit,
            '--json',
            '--platform', plataforma,
            termo
        ]
        
        return self._executar_busca(comando, "buscar_por_plataforma")
    
    def buscar_por_tipo(self, termo: str, tipo: str) -> Dict[str, Any]:
        """
        Busca exploits por tipo
        Args:
            termo (str): Termo de busca
            tipo (str): Tipo de exploit (remote, local, dos, etc.)
        Returns:
            Dict[str, Any]: Resultados da busca
        """
        comando = [
            self.binario_searchsploit,
            '--json',
            '--type', tipo,
            termo
        ]
        
        return self._executar_busca(comando, "buscar_por_tipo")
    
    def buscar_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Busca exploits por CVE ID
        Args:
            cve_id (str): ID do CVE (ex: CVE-2021-44228)
        Returns:
            Dict[str, Any]: Resultados da busca
        """
        comando = [self.binario_searchsploit, '--json', '--cve', cve_id]
        
        return self._executar_busca(comando, "buscar_cve")
    
    def buscar_multiplos_termos(self, termos: List[str]) -> Dict[str, Any]:
        """
        Busca exploits para múltiplos termos
        Args:
            termos (List[str]): Lista de termos de busca
        Returns:
            Dict[str, Any]: Resultados consolidados da busca
        """
        resultados_consolidados = {
            'sucesso': True,
            'tipo_varredura': 'buscar_multiplos_termos',
            'timestamp': datetime.now().isoformat(),
            'dados': {
                'exploits_por_termo': {},
                'resumo': {
                    'total_termos': len(termos),
                    'total_exploits': 0,
                    'exploits_unicos': set()
                }
            },
            'erro': None
        }
        
        for termo in termos:
            resultado = self.buscar_exploits(termo)
            
            if resultado['sucesso']:
                exploits = resultado['dados']['exploits']
                resultados_consolidados['dados']['exploits_por_termo'][termo] = exploits
                
                for exploit in exploits:
                    exploit_id = exploit.get('EDB-ID', '')
                    if exploit_id:
                        resultados_consolidados['dados']['resumo']['exploits_unicos'].add(exploit_id)
        
        resultados_consolidados['dados']['resumo']['total_exploits'] = len(
            resultados_consolidados['dados']['resumo']['exploits_unicos']
        )
        resultados_consolidados['dados']['resumo']['exploits_unicos'] = list(
            resultados_consolidados['dados']['resumo']['exploits_unicos']
        )
        
        return resultados_consolidados
    
    def atualizar_base_dados(self) -> Dict[str, Any]:
        """
        Atualiza base de dados do SearchSploit
        Returns:
            Dict[str, Any]: Resultado da atualização
        """
        comando = [self.binario_searchsploit, '--update']
        
        resultado = {
            'sucesso': False,
            'timestamp': datetime.now().isoformat(),
            'comando': ' '.join(comando),
            'erro': None
        }
        
        try:
            self.logger.info("Atualizando base de dados do SearchSploit...")
            
            processo = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            resultado['codigo_saida'] = processo.returncode
            resultado['saida_padrao'] = processo.stdout
            resultado['saida_erro'] = processo.stderr
            
            if processo.returncode == 0:
                resultado['sucesso'] = True
                self.logger.info("Base de dados atualizada com sucesso")
            else:
                resultado['erro'] = f"Erro na atualização: {processo.stderr}"
                self.logger.error(resultado['erro'])
                
        except Exception as e:
            resultado['erro'] = f"Erro na atualização: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def _executar_busca(self, comando: List[str], tipo_busca: str) -> Dict[str, Any]:
        """
        Executa comando SearchSploit e processa resultados
        Args:
            comando (List[str]): Comando completo do SearchSploit
            tipo_busca (str): Tipo da busca para logging
        Returns:
            Dict[str, Any]: Resultados processados da busca
        """
        resultado = {
            'sucesso': False,
            'tipo_varredura': tipo_busca,
            'comando': ' '.join(comando),
            'timestamp': datetime.now().isoformat(),
            'dados': {},
            'erro': None
        }
        
        try:
            self.logger.info(f"Executando {tipo_busca}: {' '.join(comando)}")
            
            processo = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=self.timeout_padrao
            )
            
            resultado['codigo_saida'] = processo.returncode
            resultado['saida_padrao'] = processo.stdout
            resultado['saida_erro'] = processo.stderr
            
            if processo.returncode == 0 or processo.stdout:
                resultado['dados'] = self._processar_saida_searchsploit(processo.stdout)
                resultado['sucesso'] = True
                self.logger.info(f"{tipo_busca} concluída com sucesso")
            else:
                resultado['erro'] = f"SearchSploit retornou código {processo.returncode}: {processo.stderr}"
                self.logger.error(resultado['erro'])
            
        except subprocess.TimeoutExpired:
            resultado['erro'] = f"Timeout na execução da busca ({self.timeout_padrao}s)"
            self.logger.error(resultado['erro'])
        except Exception as e:
            resultado['erro'] = f"Erro na execução: {str(e)}"
            self.logger.error(resultado['erro'])
        
        return resultado
    
    def _processar_saida_searchsploit(self, saida: str) -> Dict[str, Any]:
        """
        Processa saída JSON do SearchSploit
        Args:
            saida (str): Saída JSON do comando SearchSploit
        Returns:
            Dict[str, Any]: Dados estruturados da busca
        """
        dados = {
            'exploits': [],
            'resumo': {
                'total_exploits': 0,
                'por_plataforma': {},
                'por_tipo': {},
                'por_data': {},
                'exploits_verificados': 0
            }
        }
        
        try:
            # SearchSploit retorna JSON válido
            json_data = json.loads(saida)
            
            if 'RESULTS_EXPLOIT' in json_data:
                exploits_raw = json_data['RESULTS_EXPLOIT']
                
                for exploit_raw in exploits_raw:
                    exploit = {
                        'edb_id': exploit_raw.get('EDB-ID', ''),
                        'data': exploit_raw.get('Date', ''),
                        'autor': exploit_raw.get('Author', ''),
                        'tipo': exploit_raw.get('Type', ''),
                        'plataforma': exploit_raw.get('Platform', ''),
                        'titulo': exploit_raw.get('Title', ''),
                        'caminho': exploit_raw.get('Path', ''),
                        'verificado': exploit_raw.get('Verified', False)
                    }
                    
                    dados['exploits'].append(exploit)
                    
                    # Atualizar resumo
                    plataforma = exploit['plataforma']
                    if plataforma not in dados['resumo']['por_plataforma']:
                        dados['resumo']['por_plataforma'][plataforma] = 0
                    dados['resumo']['por_plataforma'][plataforma] += 1
                    
                    tipo = exploit['tipo']
                    if tipo not in dados['resumo']['por_tipo']:
                        dados['resumo']['por_tipo'][tipo] = 0
                    dados['resumo']['por_tipo'][tipo] += 1
                    
                    if exploit['data']:
                        ano = exploit['data'][:4] if len(exploit['data']) >= 4 else 'Unknown'
                        if ano not in dados['resumo']['por_data']:
                            dados['resumo']['por_data'][ano] = 0
                        dados['resumo']['por_data'][ano] += 1
                    
                    if exploit['verificado']:
                        dados['resumo']['exploits_verificados'] += 1
            
            dados['resumo']['total_exploits'] = len(dados['exploits'])
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Erro ao decodificar JSON: {str(e)}")
        except Exception as e:
            self.logger.error(f"Erro ao processar saída SearchSploit: {str(e)}")
        
        return dados
    
    def gerar_relatorio_resumido(self, resultados: Dict[str, Any]) -> str:
        """
        Gera relatório resumido da busca
        Args:
            resultados (Dict[str, Any]): Resultados da busca
        Returns:
            str: Relatório em formato texto
        """
        if not resultados.get('sucesso'):
            return f"Erro na busca: {resultados.get('erro', 'Erro desconhecido')}"
        
        dados = resultados.get('dados', {})
        resumo = dados.get('resumo', {})
        
        relatorio = []
        relatorio.append("=" * 60)
        relatorio.append(f"RELATÓRIO SEARCHSPLOIT - {resultados['tipo_varredura'].upper()}")
        relatorio.append("=" * 60)
        relatorio.append(f"Timestamp: {resultados['timestamp']}")
        relatorio.append(f"Comando: {resultados['comando']}")
        relatorio.append("")
        
        # Resumo
        relatorio.append("RESUMO:")
        relatorio.append(f"  Exploits Encontrados: {resumo.get('total_exploits', 0)}")
        relatorio.append(f"  Exploits Verificados: {resumo.get('exploits_verificados', 0)}")
        relatorio.append("")
        
        # Por plataforma
        por_plataforma = resumo.get('por_plataforma', {})
        if por_plataforma:
            relatorio.append("POR PLATAFORMA:")
            for plataforma, count in sorted(por_plataforma.items()):
                relatorio.append(f"  {plataforma}: {count}")
            relatorio.append("")
        
        # Por tipo
        por_tipo = resumo.get('por_tipo', {})
        if por_tipo:
            relatorio.append("POR TIPO:")
            for tipo, count in sorted(por_tipo.items()):
                relatorio.append(f"  {tipo}: {count}")
            relatorio.append("")
        
        # Exploits encontrados
        exploits = dados.get('exploits', [])
        if exploits:
            relatorio.append("EXPLOITS ENCONTRADOS:")
            for exploit in exploits[:10]:  # Máximo 10
                verificado = " [VERIFICADO]" if exploit.get('verificado') else ""
                relatorio.append(f"  • EDB-{exploit.get('edb_id', 'N/A')}: {exploit.get('titulo', 'N/A')}{verificado}")
                relatorio.append(f"    Plataforma: {exploit.get('plataforma', 'N/A')} | Tipo: {exploit.get('tipo', 'N/A')}")
                relatorio.append("")
            
            if len(exploits) > 10:
                relatorio.append(f"  ... e mais {len(exploits) - 10} exploits")
        
        return "\n".join(relatorio)
    
    def obter_categorias_disponiveis(self) -> Dict[str, List[str]]:
        """
        Retorna categorias disponíveis para busca
        Returns:
            Dict[str, List[str]]: Dicionário com categorias
        """
        return {
            'plataformas': [
                'linux', 'windows', 'macos', 'unix', 'bsd',
                'solaris', 'aix', 'hpux', 'android', 'ios'
            ],
            'tipos': [
                'remote', 'local', 'dos', 'webapps', 'shellcode',
                'papers', 'hardware', 'multiple'
            ]
        }


if __name__ == "__main__":
    # Teste do módulo
    varredura = VarreduraSearchSploit()
    
    if varredura.verificar_searchsploit():
        print("SearchSploit está disponível!")
        
        categorias = varredura.obter_categorias_disponiveis()
        print("Plataformas:", ', '.join(categorias['plataformas']))
        print("Tipos:", ', '.join(categorias['tipos']))
        
        termo = input("Digite o termo para busca de exploits: ").strip()
        if termo:
            print(f"Buscando exploits para '{termo}'...")
            resultado = varredura.buscar_exploits(termo)
            
            if resultado['sucesso']:
                print("\nRelatório da Busca:")
                print(varredura.gerar_relatorio_resumido(resultado))
            else:
                print(f"Erro na busca: {resultado['erro']}")
    else:
        print("SearchSploit não está disponível. Instale o SearchSploit para continuar.")