#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sistema de logging centralizado com recursos avançados
Inclui rotação de arquivos, níveis múltiplos e mascaramento de dados sensíveis
"""

import os
import re
import logging
import logging.handlers
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

from core.configuracao import obter_config

class MascaradorDadosSensiveis(logging.Filter):
    """Filtro para mascarar dados sensíveis nos logs"""
    
    def __init__(self):
        super().__init__()
        # Padrões para detectar dados sensíveis
        self.padroes_sensiveis = [
            (re.compile(r'(api[_-]?key["\s]*[:=]["\s]*)([a-zA-Z0-9_-]{20,})(["\s]*)', re.IGNORECASE), r'\1***MASKED***\3'),
            (re.compile(r'(password["\s]*[:=]["\s]*)([^"\s,}]+)(["\s]*)', re.IGNORECASE), r'\1***MASKED***\3'),
            (re.compile(r'(token["\s]*[:=]["\s]*)([a-zA-Z0-9_-]{20,})(["\s]*)', re.IGNORECASE), r'\1***MASKED***\3'),
            (re.compile(r'(authorization["\s]*:["\s]*bearer["\s]+)([a-zA-Z0-9_-]{20,})(["\s]*)', re.IGNORECASE), r'\1***MASKED***\3'),
            (re.compile(r'(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)'), r'***.***.***.***'),  # IPs parcialmente mascarados
        ]
    
    def filter(self, record):
        """
        Filtra e mascara dados sensíveis na mensagem de log
        
        Args:
            record: Registro de log
            
        Returns:
            bool: True para manter o registro
        """
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            mensagem = record.msg
            
            # Aplicar mascaramento para cada padrão
            for padrao, substituicao in self.padroes_sensiveis:
                mensagem = padrao.sub(substituicao, mensagem)
            
            record.msg = mensagem
        
        return True

class GerenciadorLog:
    """Gerenciador centralizado de logging para o sistema"""
    
    def __init__(self):
        """Inicializa o gerenciador de logging"""
        self.configurado = False
        self.loggers = {}
        self.mascarar_dados = obter_config('logging.mascarar_dados_sensiveis', True)
        
        # Configurações padrão
        self.nivel_padrao = obter_config('logging.nivel', 'CRITICAL')  # Silencioso por padrão
        self.arquivo_log = obter_config('logging.arquivo', 'logs/sistema.log')
        self.max_tamanho_mb = obter_config('logging.max_tamanho_mb', 10)
        self.backup_count = obter_config('logging.backup_count', 5)
        self.formato = obter_config('logging.formato', 
                                   '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        self.configurar_logging()
    
    def configurar_logging(self):
        """Configura o sistema de logging"""
        try:
            # Criar diretório de logs se não existir
            caminho_log = Path(self.arquivo_log)
            caminho_log.parent.mkdir(parents=True, exist_ok=True)
            
            # Configurar logger raiz
            root_logger = logging.getLogger()
            root_logger.setLevel(getattr(logging, self.nivel_padrao.upper()))
            
            # Remover handlers existentes
            for handler in root_logger.handlers[:]:
                root_logger.removeHandler(handler)
            
            # Criar formatador
            formatador = logging.Formatter(
                self.formato,
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            # Handler para console
            handler_console = logging.StreamHandler()
            handler_console.setLevel(getattr(logging, self.nivel_padrao.upper()))
            handler_console.setFormatter(formatador)
            
            # Adicionar mascaramento se habilitado
            if self.mascarar_dados:
                handler_console.addFilter(MascaradorDadosSensiveis())
            
            root_logger.addHandler(handler_console)
            
            # Handler para arquivo com rotação
            handler_arquivo = logging.handlers.RotatingFileHandler(
                self.arquivo_log,
                maxBytes=self.max_tamanho_mb * 1024 * 1024,  # Converter MB para bytes
                backupCount=self.backup_count,
                encoding='utf-8'
            )
            handler_arquivo.setLevel(getattr(logging, self.nivel_padrao.upper()))
            handler_arquivo.setFormatter(formatador)
            
            # Adicionar mascaramento se habilitado
            if self.mascarar_dados:
                handler_arquivo.addFilter(MascaradorDadosSensiveis())
            
            root_logger.addHandler(handler_arquivo)
            
            self.configurado = True
            
            # Log de inicialização apenas se não estiver em modo silencioso
            if self.nivel_padrao.upper() != 'CRITICAL':
                logger = self.obter_logger('GerenciadorLog')
                logger.info("Sistema de logging configurado com sucesso")
                logger.info(f"Arquivo de log: {self.arquivo_log}")
                logger.info(f"Nível de log: {self.nivel_padrao}")
                logger.info(f"Mascaramento de dados: {'Habilitado' if self.mascarar_dados else 'Desabilitado'}")
            
        except Exception as e:
            print(f"Erro ao configurar logging: {str(e)}")
            self.configurado = False
    
    def obter_logger(self, nome: str) -> logging.Logger:
        """
        Obtém ou cria um logger com nome específico
        
        Args:
            nome (str): Nome do logger
            
        Returns:
            logging.Logger: Instância do logger
        """
        if nome not in self.loggers:
            self.loggers[nome] = logging.getLogger(nome)
        
        return self.loggers[nome]
    
    def definir_nivel(self, nivel: str):
        """
        Define o nível de logging globalmente
        
        Args:
            nivel (str): Nível de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        try:
            nivel_logging = getattr(logging, nivel.upper())
            logging.getLogger().setLevel(nivel_logging)
            
            # Atualizar todos os handlers (console e arquivo)
            for handler in logging.getLogger().handlers:
                handler.setLevel(nivel_logging)
            
            # Só fazer log se não for CRITICAL (para evitar spam quando silencioso)
            if nivel.upper() != 'CRITICAL':
                logger = self.obter_logger('GerenciadorLog')
                logger.info(f"Nível de logging alterado para: {nivel.upper()}")
            
        except AttributeError:
            logger = self.obter_logger('GerenciadorLog')
            logger.error(f"Nível de logging inválido: {nivel}")
    
    def log_comando_sistema(self, comando: str, resultado: Dict[str, Any]):
        """
        Log especializado para comandos do sistema
        
        Args:
            comando (str): Comando executado
            resultado (Dict[str, Any]): Resultado da execução
        """
        logger = self.obter_logger('ComandoSistema')
        
        if resultado.get('sucesso', False):
            logger.info(f"Comando executado: {comando}")
            if 'dados' in resultado:
                logger.debug(f"Resultado: {resultado['dados']}")
        else:
            logger.error(f"Falha no comando: {comando}")
            if 'erro' in resultado:
                logger.error(f"Erro: {resultado['erro']}")
    
    def log_varredura_nmap(self, tipo_varredura: str, alvo: str, resultado: Dict[str, Any]):
        """
        Log especializado para varreduras Nmap
        
        Args:
            tipo_varredura (str): Tipo da varredura
            alvo (str): Alvo da varredura
            resultado (Dict[str, Any]): Resultado da varredura
        """
        logger = self.obter_logger('VarreduraNmap')
        
        if resultado.get('sucesso', False):
            dados = resultado.get('dados', {})
            resumo = dados.get('resumo', {})
            
            logger.info(f"Varredura {tipo_varredura} concluída em {alvo}")
            logger.info(f"Hosts ativos: {resumo.get('hosts_ativos', 0)}")
            logger.info(f"Portas abertas: {resumo.get('portas_abertas', 0)}")
            logger.info(f"Serviços detectados: {resumo.get('servicos_detectados', 0)}")
            logger.info(f"Vulnerabilidades encontradas: {resumo.get('vulnerabilidades', 0)}")
        else:
            logger.error(f"Falha na varredura {tipo_varredura} em {alvo}")
            if 'erro' in resultado:
                logger.error(f"Erro: {resultado['erro']}")
    
    def log_api_gemini(self, operacao: str, sucesso: bool, detalhes: Optional[str] = None):
        """
        Log especializado para operações com API Gemini
        
        Args:
            operacao (str): Tipo de operação (conectar, enviar_mensagem, etc.)
            sucesso (bool): Se a operação foi bem-sucedida
            detalhes (str): Detalhes adicionais
        """
        logger = self.obter_logger('APIGemini')
        
        if sucesso:
            logger.info(f"API Gemini - {operacao}: Sucesso")
            if detalhes:
                logger.debug(f"Detalhes: {detalhes}")
        else:
            logger.error(f"API Gemini - {operacao}: Falha")
            if detalhes:
                logger.error(f"Erro: {detalhes}")
    
    def log_sessao_pentest(self, evento: str, detalhes: Dict[str, Any]):
        """
        Log especializado para sessões de pentest
        
        Args:
            evento (str): Tipo de evento
            detalhes (Dict[str, Any]): Detalhes do evento
        """
        logger = self.obter_logger('SessaoPentest')
        
        timestamp = datetime.now().isoformat()
        logger.info(f"Sessão Pentest - {evento}")
        logger.info(f"Timestamp: {timestamp}")
        
        for chave, valor in detalhes.items():
            logger.info(f"{chave}: {valor}")
    
    def obter_estatisticas_log(self) -> Dict[str, Any]:
        """
        Obtém estatísticas dos logs
        
        Returns:
            Dict[str, Any]: Estatísticas dos logs
        """
        estatisticas = {
            'arquivo_principal': self.arquivo_log,
            'tamanho_arquivo': 0,
            'arquivos_backup': [],
            'configurado': self.configurado,
            'nivel_atual': self.nivel_padrao,
            'mascaramento_ativo': self.mascarar_dados
        }
        
        try:
            # Tamanho do arquivo principal
            if Path(self.arquivo_log).exists():
                estatisticas['tamanho_arquivo'] = Path(self.arquivo_log).stat().st_size
            
            # Arquivos de backup
            diretorio_log = Path(self.arquivo_log).parent
            nome_base = Path(self.arquivo_log).stem
            extensao = Path(self.arquivo_log).suffix
            
            for i in range(1, self.backup_count + 1):
                arquivo_backup = diretorio_log / f"{nome_base}{extensao}.{i}"
                if arquivo_backup.exists():
                    estatisticas['arquivos_backup'].append({
                        'arquivo': str(arquivo_backup),
                        'tamanho': arquivo_backup.stat().st_size
                    })
        
        except Exception as e:
            logger = self.obter_logger('GerenciadorLog')
            logger.error(f"Erro ao obter estatísticas: {str(e)}")
        
        return estatisticas
    
    def rotacionar_logs_manualmente(self) -> bool:
        """
        Força rotação manual dos logs
        
        Returns:
            bool: True se a rotação foi bem-sucedida
        """
        try:
            for handler in logging.getLogger().handlers:
                if isinstance(handler, logging.handlers.RotatingFileHandler):
                    handler.doRollover()
            
            logger = self.obter_logger('GerenciadorLog')
            logger.info("Rotação manual de logs executada")
            return True
            
        except Exception as e:
            print(f"Erro na rotação manual: {str(e)}")
            return False
    
    def limpar_logs_antigos(self, dias: int = 30) -> bool:
        """
        Remove logs mais antigos que o número especificado de dias
        
        Args:
            dias (int): Número de dias para manter os logs
            
        Returns:
            bool: True se a limpeza foi bem-sucedida
        """
        try:
            from datetime import timedelta
            
            diretorio_log = Path(self.arquivo_log).parent
            limite_tempo = datetime.now() - timedelta(days=dias)
            
            arquivos_removidos = 0
            for arquivo in diretorio_log.glob("*.log*"):
                if arquivo.stat().st_mtime < limite_tempo.timestamp():
                    arquivo.unlink()
                    arquivos_removidos += 1
            
            logger = self.obter_logger('GerenciadorLog')
            logger.info(f"Limpeza de logs: {arquivos_removidos} arquivos removidos")
            return True
            
        except Exception as e:
            logger = self.obter_logger('GerenciadorLog')
            logger.error(f"Erro na limpeza de logs: {str(e)}")
            return False


# Instância global do gerenciador de log
log_manager = GerenciadorLog()


def obter_logger(nome: str) -> logging.Logger:
    """
    Função auxiliar para obter logger
    
    Args:
        nome (str): Nome do logger
        
    Returns:
        logging.Logger: Instância do logger
    """
    return log_manager.obter_logger(nome)


if __name__ == "__main__":
    # Teste do sistema de logging
    logger = obter_logger('Teste')
    
    logger.debug("Mensagem de debug")
    logger.info("Mensagem de informação")
    logger.warning("Mensagem de aviso")
    logger.error("Mensagem de erro")
    logger.critical("Mensagem crítica")
    
    # Teste de mascaramento
    logger.info("API Key: AIzaSyDvgL5ssyTOQk5x-9Fl7tLV3hy1H62Q2UQ")
    logger.info("Password: minha_senha_secreta")
    logger.info("Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
    logger.info("IP: 192.168.1.100")
    
    # Estatísticas
    stats = log_manager.obter_estatisticas_log()
    print("\nEstatísticas do Log:")
    for chave, valor in stats.items():
        print(f"  {chave}: {valor}")