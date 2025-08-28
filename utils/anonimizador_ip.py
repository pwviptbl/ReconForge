#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Anonimizador de IPs para contexto enviado à IA
Mantém funcionalidade preservando privacidade
"""

import hashlib
import ipaddress
from typing import Dict, List, Any, Optional, Tuple
import json
import re

class AnonimizadorIP:
    """Classe para anonimização segura de IPs em contextos para IA"""
    
    def __init__(self, seed: Optional[str] = None):
        """
        Inicializa o anonimizador
        Args:
            seed (str, optional): Seed para reproduzibilidade (opcional)
        """
        self.seed = seed or "varredura_ia_seed"
        self.mapeamento_real_para_anonimo: Dict[str, str] = {}
        self.mapeamento_anonimo_para_real: Dict[str, str] = {}
        self.contador_ips = 0
        
        # Padrões de rede para preservar informações relevantes para a IA
        self.padroes_rede = {
            'privada': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
            'localhost': ['127.0.0.0/8'],
            'link_local': ['169.254.0.0/16'],
            'multicast': ['224.0.0.0/4']
        }
    
    def _gerar_ip_anonimo(self, ip_real: str) -> str:
        """
        Gera IP anônimo consistente baseado no real
        Args:
            ip_real (str): IP real
        Returns:
            str: IP anônimo
        """
        # Usar hash consistente
        hash_input = f"{self.seed}:{ip_real}"
        hash_hex = hashlib.md5(hash_input.encode()).hexdigest()
        
        # Determinar tipo de rede para preservar contexto
        tipo_rede = self._classificar_ip(ip_real)
        
        # Gerar IP anônimo baseado no tipo
        if tipo_rede == 'privada':
            # Manter como rede privada para contexto
            base = "192.168"
            # Usar hash para gerar últimos octetos
            octeto3 = int(hash_hex[:2], 16) % 256
            octeto4 = int(hash_hex[2:4], 16) % 254 + 1  # Evitar .0
            return f"{base}.{octeto3}.{octeto4}"
        
        elif tipo_rede == 'localhost':
            return "127.0.0.1"
        
        elif tipo_rede == 'link_local':
            return "169.254.1.1"
        
        elif tipo_rede == 'multicast':
            return "224.0.0.1"
        
        else:  # IP público
            # Usar rede de documentação RFC 5737
            base = "203.0.113"  # TEST-NET-3
            octeto4 = int(hash_hex[:2], 16) % 254 + 1
            return f"{base}.{octeto4}"
    
    def _classificar_ip(self, ip: str) -> str:
        """
        Classifica tipo de IP para preservar contexto de rede
        Args:
            ip (str): IP a classificar
        Returns:
            str: Tipo de rede
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            for tipo, redes in self.padroes_rede.items():
                for rede in redes:
                    if ip_obj in ipaddress.ip_network(rede):
                        return tipo
            
            return 'publica'
            
        except Exception:
            return 'invalida'
    
    def anonimizar_ip(self, ip_real: str) -> str:
        """
        Anonimiza um IP específico
        Args:
            ip_real (str): IP real
        Returns:
            str: IP anônimo
        """
        if ip_real in self.mapeamento_real_para_anonimo:
            return self.mapeamento_real_para_anonimo[ip_real]
        
        ip_anonimo = self._gerar_ip_anonimo(ip_real)
        
        # Garantir unicidade
        while ip_anonimo in self.mapeamento_anonimo_para_real:
            self.contador_ips += 1
            # Modificar ligeiramente se houver colisão
            parts = ip_anonimo.split('.')
            parts[-1] = str((int(parts[-1]) + self.contador_ips) % 254 + 1)
            ip_anonimo = '.'.join(parts)
        
        # Armazenar mapeamento
        self.mapeamento_real_para_anonimo[ip_real] = ip_anonimo
        self.mapeamento_anonimo_para_real[ip_anonimo] = ip_real
        
        return ip_anonimo
    
    def anonimizar_texto(self, texto: str) -> Tuple[str, Dict[str, str]]:
        """
        Anonimiza IPs em texto livre
        Args:
            texto (str): Texto com IPs
        Returns:
            Tuple[str, Dict]: Texto anonimizado e mapeamento usado
        """
        # Padrão para encontrar IPs (simples)
        padrao_ip = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        def substituir_ip(match):
            ip_real = match.group(0)
            # Validar se é realmente um IP válido
            try:
                ipaddress.ip_address(ip_real)
                return self.anonimizar_ip(ip_real)
            except:
                return ip_real  # Não é IP válido
        
        texto_anonimizado = re.sub(padrao_ip, substituir_ip, texto)
        
        # Retornar mapeamento usado nesta operação
        mapeamento_usado = {k: v for k, v in self.mapeamento_real_para_anonimo.items() 
                           if k in texto}
        
        return texto_anonimizado, mapeamento_usado
    
    def anonimizar_estrutura_dados(self, dados: Any) -> Tuple[Any, Dict[str, str]]:
        """
        Anonimiza IPs em estruturas de dados complexas
        Args:
            dados: Dados a anonimizar (dict, list, str, etc)
        Returns:
            Tuple: Dados anonimizados e mapeamento usado
        """
        mapeamento_usado = {}
        
        def processar_recursivo(obj):
            if isinstance(obj, dict):
                resultado = {}
                for chave, valor in obj.items():
                    # Verificar se a chave indica IP (somente se chave é string)
                    if (isinstance(chave, str) and 
                        any(termo in chave.lower() for termo in ['ip', 'endereco', 'address', 'host'])):
                        if isinstance(valor, str) and self._é_ip_válido(valor):
                            resultado[chave] = self.anonimizar_ip(valor)
                            mapeamento_usado[valor] = resultado[chave]
                        else:
                            resultado[chave] = processar_recursivo(valor)
                    # Se a chave não é string, manter como está (ex: portas numéricas)
                    elif not isinstance(chave, str):
                        resultado[chave] = processar_recursivo(valor)
                    else:
                        resultado[chave] = processar_recursivo(valor)
                return resultado
            
            elif isinstance(obj, list):
                return [processar_recursivo(item) for item in obj]
            
            elif isinstance(obj, str):
                # Verificar se é um IP direto
                if self._é_ip_válido(obj):
                    ip_anonimo = self.anonimizar_ip(obj)
                    mapeamento_usado[obj] = ip_anonimo
                    return ip_anonimo
                else:
                    # Buscar IPs no texto
                    texto_anonimizado, mapeamento_texto = self.anonimizar_texto(obj)
                    mapeamento_usado.update(mapeamento_texto)
                    return texto_anonimizado
            
            else:
                return obj
        
        dados_anonimizados = processar_recursivo(dados)
        return dados_anonimizados, mapeamento_usado
    
    def _é_ip_válido(self, ip: str) -> bool:
        """
        Verifica se string é um IP válido
        Args:
            ip (str): String a verificar
        Returns:
            bool: True se for IP válido
        """
        try:
            ipaddress.ip_address(ip.strip())
            return True
        except:
            return False
    
    def obter_ip_real(self, ip_anonimo: str) -> Optional[str]:
        """
        Obtém IP real a partir do anônimo
        Args:
            ip_anonimo (str): IP anônimo
        Returns:
            Optional[str]: IP real ou None
        """
        return self.mapeamento_anonimo_para_real.get(ip_anonimo)
    
    def gerar_resumo_anonimizacao(self) -> Dict[str, Any]:
        """
        Gera resumo da anonimização realizada
        Returns:
            Dict: Resumo estatístico
        """
        tipos_rede = {}
        for ip_real, ip_anonimo in self.mapeamento_real_para_anonimo.items():
            tipo = self._classificar_ip(ip_real)
            tipos_rede[tipo] = tipos_rede.get(tipo, 0) + 1
        
        return {
            'total_ips_anonimizados': len(self.mapeamento_real_para_anonimo),
            'tipos_rede_encontrados': tipos_rede,
            'exemplo_mapeamento': {
                f"TIPO_{self._classificar_ip(ip_real).upper()}": ip_anonimo 
                for ip_real, ip_anonimo in list(self.mapeamento_real_para_anonimo.items())[:3]
            }
        }
    
    def limpar_mapeamentos(self):
        """Limpa todos os mapeamentos (use com cuidado)"""
        self.mapeamento_real_para_anonimo.clear()
        self.mapeamento_anonimo_para_real.clear()
        self.contador_ips = 0


# Funções utilitárias para uso direto

def anonimizar_contexto_ia(dados_contexto: Dict[str, Any], seed: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Função utilitária para anonimizar contexto antes de enviar para IA
    Args:
        dados_contexto (Dict): Dados do contexto
        seed (str, optional): Seed para reproduzibilidade
    Returns:
        Tuple[Dict, Dict]: Contexto anonimizado e mapeamento
    """
    anonimizador = AnonimizadorIP(seed)
    contexto_anonimo, mapeamento = anonimizador.anonimizar_estrutura_dados(dados_contexto)
    
    # Adicionar aviso no contexto
    if isinstance(contexto_anonimo, dict):
        contexto_anonimo['_aviso_anonimizacao'] = {
            'status': 'IPs anonimizados por segurança',
            'preservado': 'Tipos de rede e estrutura mantidos',
            'total_anonimizado': len(mapeamento)
        }
    
    return contexto_anonimo, mapeamento


def criar_contexto_seguro_para_ia(dados_originais: Dict[str, Any]) -> Dict[str, Any]:
    """
    Cria contexto seguro para envio à IA removendo/mascarando informações sensíveis
    Args:
        dados_originais (Dict): Dados originais
    Returns:
        Dict: Contexto seguro
    """
    # Anonimizar IPs
    contexto_anonimo, mapeamento = anonimizar_contexto_ia(dados_originais)
    
    # Remover outras informações potencialmente sensíveis
    campos_sensiveis = [
        'credenciais', 'senhas', 'tokens', 'chaves',
        'caminhos_completos', 'paths', 'usuarios',
        'mac_address', 'serial_numbers'
    ]
    
    def limpar_recursivo(obj):
        if isinstance(obj, dict):
            resultado = {}
            for chave, valor in obj.items():
                # Verificar se chave é string antes de usar lower()
                if isinstance(chave, str):
                    chave_lower = chave.lower()
                    # Verificar se chave contém informação sensível
                    if any(termo in chave_lower for termo in campos_sensiveis):
                        resultado[chave] = "[REMOVIDO_POR_SEGURANÇA]"
                    else:
                        resultado[chave] = limpar_recursivo(valor)
                else:
                    # Se chave não é string (ex: número), apenas processar o valor
                    resultado[chave] = limpar_recursivo(valor)
            return resultado
        elif isinstance(obj, list):
            return [limpar_recursivo(item) for item in obj]
        else:
            return obj
    
    contexto_limpo = limpar_recursivo(contexto_anonimo)
    
    return contexto_limpo


if __name__ == "__main__":
    # Teste do anonimizador
    print("🔒 Teste do Anonimizador de IPs")
    
    # Dados de teste
    dados_teste = {
        'alvo_original': '192.168.1.100',
        'ips_descobertos': ['192.168.1.100', '10.0.0.1', '203.0.113.50'],
        'portas_abertas': {
            '192.168.1.100': [22, 80, 443],
            '10.0.0.1': [80, 8080]
        },
        'servicos_detectados': {
            '192.168.1.100': {
                80: {'servico': 'http'},
                443: {'servico': 'https'}
            }
        },
        'descricao': 'Scan do host 192.168.1.100 revelou serviços em 10.0.0.1'
    }
    
    print("\n📋 Dados originais:")
    print(json.dumps(dados_teste, indent=2, ensure_ascii=False))
    
    # Testar anonimização
    anonimizador = AnonimizadorIP("teste_seed")
    dados_anonimos, mapeamento = anonimizador.anonimizar_estrutura_dados(dados_teste)
    
    print("\n🎭 Dados anonimizados:")
    print(json.dumps(dados_anonimos, indent=2, ensure_ascii=False))
    
    print("\n🗝️ Mapeamento de IPs:")
    for real, anonimo in mapeamento.items():
        print(f"  {real} → {anonimo}")
    
    print("\n📊 Resumo da anonimização:")
    resumo = anonimizador.gerar_resumo_anonimizacao()
    print(json.dumps(resumo, indent=2, ensure_ascii=False))
    
    print("\n🔄 Teste de reversão:")
    for anonimo, real in anonimizador.mapeamento_anonimo_para_real.items():
        print(f"  {anonimo} → {real}")
    
    print("\n✅ Teste concluído!")
    print("💡 Os IPs agora podem ser enviados à IA com segurança!")
