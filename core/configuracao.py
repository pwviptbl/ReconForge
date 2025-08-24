#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de configuração do sistema de pentest
Gerencia as configurações em YAML com suporte a variáveis de ambiente
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path

class GerenciadorConfiguracao:
    """Gerenciador de configurações do sistema"""
    
    def __init__(self, arquivo_config: Optional[str] = None):
        """
        Inicializa o gerenciador de configuração
        Args:
            arquivo_config (str): Caminho para o arquivo de configuração
        """
        self.logger = logging.getLogger(__name__)
        
        # Definir caminho padrão do arquivo de configuração
        if arquivo_config is None:
            self.caminho_config = Path(__file__).parent / "default.yaml"
        else:
            self.caminho_config = Path(arquivo_config)
        
        self.configuracoes = {}
        self.carregar_configuracoes()
    
    def carregar_configuracoes(self) -> bool:
        """
        Carrega as configurações do arquivo YAML
        Returns:
            bool: True se carregou com sucesso, False caso contrário
        """
        try:
            if not self.caminho_config.exists():
                self.logger.error(f"Arquivo de configuração não encontrado: {self.caminho_config}")
                return False
            
            with open(self.caminho_config, 'r', encoding='utf-8') as arquivo:
                self.configuracoes = yaml.safe_load(arquivo)
            
            # Expandir variáveis de ambiente
            self._expandir_variaveis_ambiente(self.configuracoes)
            
            self.logger.info(f"Configurações carregadas de: {self.caminho_config}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao carregar configurações: {str(e)}")
            return False
    
    def _expandir_variaveis_ambiente(self, configuracoes: Dict[str, Any]):
        """
        Expande variáveis de ambiente nas configurações
        Args:
            configuracoes (Dict): Dicionário de configurações
        """
        for chave, valor in configuracoes.items():
            if isinstance(valor, dict):
                self._expandir_variaveis_ambiente(valor)
            elif isinstance(valor, str) and valor.startswith("${") and valor.endswith("}"):
                var_ambiente = valor[2:-1]  # Remove ${ e }
                configuracoes[chave] = os.getenv(var_ambiente, valor)
    
    def obter_configuracao(self, caminho: str, padrao=None) -> Any:
        """
        Obtém uma configuração específica usando notação de ponto
        Args:
            caminho (str): Caminho da configuração (ex: 'api.gemini.modelo')
            padrao: Valor padrão se não encontrar
        Returns:
            Any: Valor da configuração ou padrão
        """
        try:
            chaves = caminho.split('.')
            valor = self.configuracoes
            
            for chave in chaves:
                valor = valor[chave]
            
            return valor
            
        except (KeyError, TypeError):
            self.logger.warning(f"Configuração não encontrada: {caminho}, usando padrão: {padrao}")
            return padrao
    
    def definir_configuracao(self, caminho: str, valor: Any):
        """
        Define uma configuração específica
        Args:
            caminho (str): Caminho da configuração
            valor (Any): Valor a ser definido
        """
        chaves = caminho.split('.')
        config_atual = self.configuracoes
        
        # Navegar até o penúltimo nível
        for chave in chaves[:-1]:
            if chave not in config_atual:
                config_atual[chave] = {}
            config_atual = config_atual[chave]
        
        # Definir o valor final
        config_atual[chaves[-1]] = valor
        self.logger.info(f"Configuração definida: {caminho} = {valor}")
    
    def salvar_configuracoes(self, arquivo_destino: Optional[str] = None) -> bool:
        """
        Salva as configurações em um arquivo YAML
        Args:
            arquivo_destino (str): Caminho do arquivo de destino
        Returns:
            bool: True se salvou com sucesso, False caso contrário
        """
        try:
            caminho_destino = Path(arquivo_destino) if arquivo_destino else self.caminho_config
            
            with open(caminho_destino, 'w', encoding='utf-8') as arquivo:
                yaml.dump(self.configuracoes, arquivo, default_flow_style=False, 
                         allow_unicode=True, indent=2)
            
            self.logger.info(f"Configurações salvas em: {caminho_destino}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar configurações: {str(e)}")
            return False
    
    def validar_configuracoes(self) -> Dict[str, str]:
        """
        Valida as configurações essenciais
        Returns:
            Dict[str, str]: Dicionário com erros encontrados
        """
        erros = {}
        
        # Validar configurações da API Gemini
        if not self.obter_configuracao('api.gemini.chave_api'):
            erros['api_gemini'] = "Chave da API Gemini não configurada"
        
        # Validar modelo Gemini
        modelo = self.obter_configuracao('api.gemini.modelo')
        if not modelo or modelo != 'gemini-2.5-pro':
            erros['modelo_gemini'] = "Modelo deve ser 'gemini-2.5-pro'"
        
        # Validar configurações do Nmap
        if not self.obter_configuracao('nmap.binario'):
            erros['nmap_binario'] = "Caminho do binário Nmap não configurado"
        
        # Validar diretórios
        diretorios = [
            'banco_dados.arquivo',
            'logging.arquivo',
            'relatorios.diretorio'
        ]
        
        for dir_config in diretorios:
            caminho = self.obter_configuracao(dir_config)
            if caminho:
                dir_pai = Path(caminho).parent
                if not dir_pai.exists():
                    try:
                        dir_pai.mkdir(parents=True, exist_ok=True)
                    except Exception as e:
                        erros[dir_config] = f"Não foi possível criar diretório: {str(e)}"
        
        return erros
    
    def configuracao_interativa(self):
        """Processo interativo de configuração"""
        print("=== Configuração Interativa do Sistema de Pentest ===")
        print()
        
        # Configurar API Gemini
        print("1. Configuração da API Gemini")
        chave_atual = self.obter_configuracao('api.gemini.chave_api', '')
        if chave_atual.startswith('${'):
            chave_atual = ''
        
        if not chave_atual:
            print("Para obter sua chave API do Gemini:")
            print("1. Acesse: https://aistudio.google.com/app/apikey")
            print("2. Faça login com sua conta Google")
            print("3. Clique em 'Create API Key'")
            print("4. Copie a chave gerada")
            print()
        
        nova_chave = input(f"Chave da API Gemini [{chave_atual[:20]}...]: ").strip()
        if nova_chave:
            self.definir_configuracao('api.gemini.chave_api', nova_chave)
        
        # Configurar Nmap
        print("\n2. Configuração do Nmap")
        binario_atual = self.obter_configuracao('nmap.binario', 'nmap')
        novo_binario = input(f"Caminho do binário Nmap [{binario_atual}]: ").strip()
        if novo_binario:
            self.definir_configuracao('nmap.binario', novo_binario)
        
        # Salvar configurações
        if self.salvar_configuracoes():
            print("\n✓ Configurações salvas com sucesso!")
        else:
            print("\n✗ Erro ao salvar configurações")
        
        # Validar configurações
        erros = self.validar_configuracoes()
        if erros:
            print("\n⚠ Problemas encontrados na configuração:")
            for erro, descricao in erros.items():
                print(f"  - {erro}: {descricao}")
        else:
            print("\n✓ Todas as configurações estão válidas!")
    
    def obter_todas_configuracoes(self) -> Dict[str, Any]:
        """
        Retorna todas as configurações
        Returns:
            Dict[str, Any]: Dicionário com todas as configurações
        """
        return self.configuracoes.copy()


# Instância global do gerenciador de configuração
config = GerenciadorConfiguracao()


def obter_config(caminho: str, padrao=None) -> Any:
    """
    Função auxiliar para obter configurações
    Args:
        caminho (str): Caminho da configuração
        padrao: Valor padrão
    Returns:
        Any: Valor da configuração
    """
    return config.obter_configuracao(caminho, padrao)


if __name__ == "__main__":
    # Teste e configuração interativa
    config.configuracao_interativa()