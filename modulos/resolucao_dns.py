#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de Resolução DNS
Resolve nomes de domínio para endereços IP e coleta informações básicas
"""

import socket
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
import dns.resolver
import dns.reversename

from utils.logger import obter_logger

class ResolucaoDNS:
    """Classe para resolução DNS e coleta de informações básicas"""
    
    def __init__(self):
        """Inicializa o resolvedor DNS"""
        self.logger = obter_logger('ResolucaoDNS')
        
    def eh_ip(self, alvo: str) -> bool:
        """
        Verifica se o alvo é um endereço IP
        Args:
            alvo (str): Alvo a ser verificado
        Returns:
            bool: True se for IP, False se for domínio
        """
        # Regex para IPv4
        padrao_ipv4 = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        # Regex para IPv6 (simplificado)
        padrao_ipv6 = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
        
        return bool(re.match(padrao_ipv4, alvo) or re.match(padrao_ipv6, alvo))
    
    def resolver_dns(self, alvo: str) -> Dict[str, Any]:
        """
        Resolve DNS do alvo e coleta informações
        Args:
            alvo (str): Domínio ou IP para resolver
        Returns:
            Dict[str, Any]: Resultados da resolução DNS
        """
        resultado = {
            'timestamp_inicio': datetime.now().isoformat(),
            'alvo_original': alvo,
            'tipo_alvo': 'ip' if self.eh_ip(alvo) else 'dominio',
            'sucesso': False,
            'dados': {},
            'erro': None
        }
        
        try:
            if self.eh_ip(alvo):
                # Se já é IP, fazer resolução reversa
                resultado['dados'] = self._resolver_reverso(alvo)
            else:
                # Se é domínio, resolver para IP
                resultado['dados'] = self._resolver_direto(alvo)
            
            resultado['sucesso'] = True
            resultado['timestamp_fim'] = datetime.now().isoformat()
            
            self.logger.info(f"Resolução DNS concluída para {alvo}")
            
        except Exception as e:
            erro_msg = f"Erro na resolução DNS: {str(e)}"
            self.logger.error(erro_msg)
            resultado['erro'] = erro_msg
            resultado['timestamp_fim'] = datetime.now().isoformat()
        
        return resultado
    
    def _resolver_direto(self, dominio: str) -> Dict[str, Any]:
        """
        Resolve domínio para IP (resolução direta)
        Args:
            dominio (str): Nome do domínio
        Returns:
            Dict[str, Any]: Informações de resolução
        """
        dados = {
            'dominio': dominio,
            'ips_resolvidos': [],
            'registros_dns': {},
            'informacoes_adicionais': {}
        }
        
        try:
            # Resolução básica usando socket
            try:
                ip_principal = socket.gethostbyname(dominio)
                dados['ip_principal'] = ip_principal
                dados['ips_resolvidos'].append(ip_principal)
                self.logger.info(f"IP principal resolvido: {dominio} -> {ip_principal}")
            except socket.gaierror as e:
                self.logger.warning(f"Falha na resolução básica: {str(e)}")
                raise Exception(f"Não foi possível resolver o domínio {dominio}")
            
            # Tentar resolução DNS mais detalhada
            try:
                # Registros A
                try:
                    registros_a = dns.resolver.resolve(dominio, 'A')
                    ips_a = [str(rdata) for rdata in registros_a]
                    dados['registros_dns']['A'] = ips_a
                    
                    # Adicionar IPs únicos à lista
                    for ip in ips_a:
                        if ip not in dados['ips_resolvidos']:
                            dados['ips_resolvidos'].append(ip)
                            
                except Exception as e:
                    self.logger.debug(f"Erro ao obter registros A: {str(e)}")
                
                # Registros AAAA (IPv6)
                try:
                    registros_aaaa = dns.resolver.resolve(dominio, 'AAAA')
                    ips_aaaa = [str(rdata) for rdata in registros_aaaa]
                    dados['registros_dns']['AAAA'] = ips_aaaa
                except Exception as e:
                    self.logger.debug(f"Erro ao obter registros AAAA: {str(e)}")
                
                # Registros CNAME
                try:
                    registros_cname = dns.resolver.resolve(dominio, 'CNAME')
                    cnames = [str(rdata) for rdata in registros_cname]
                    dados['registros_dns']['CNAME'] = cnames
                except Exception as e:
                    self.logger.debug(f"Erro ao obter registros CNAME: {str(e)}")
                
                # Registros MX
                try:
                    registros_mx = dns.resolver.resolve(dominio, 'MX')
                    mx_records = [f"{rdata.preference} {rdata.exchange}" for rdata in registros_mx]
                    dados['registros_dns']['MX'] = mx_records
                except Exception as e:
                    self.logger.debug(f"Erro ao obter registros MX: {str(e)}")
                
                # Registros TXT
                try:
                    registros_txt = dns.resolver.resolve(dominio, 'TXT')
                    txt_records = [str(rdata) for rdata in registros_txt]
                    dados['registros_dns']['TXT'] = txt_records
                except Exception as e:
                    self.logger.debug(f"Erro ao obter registros TXT: {str(e)}")
                    
            except Exception as e:
                self.logger.warning(f"Resolução DNS detalhada falhou: {str(e)}")
            
            # Informações adicionais
            dados['informacoes_adicionais'] = {
                'total_ips_encontrados': len(dados['ips_resolvidos']),
                'tipos_registro_encontrados': list(dados['registros_dns'].keys()),
                'dominio_validado': True
            }
            
        except Exception as e:
            raise Exception(f"Falha na resolução direta: {str(e)}")
        
        return dados
    
    def _resolver_reverso(self, ip: str) -> Dict[str, Any]:
        """
        Resolve IP para domínio (resolução reversa)
        Args:
            ip (str): Endereço IP
        Returns:
            Dict[str, Any]: Informações de resolução reversa
        """
        dados = {
            'ip': ip,
            'dominios_resolvidos': [],
            'hostname_principal': None,
            'informacoes_adicionais': {}
        }
        
        try:
            # Resolução reversa básica usando socket
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                dados['hostname_principal'] = hostname
                dados['dominios_resolvidos'].append(hostname)
                self.logger.info(f"Hostname principal resolvido: {ip} -> {hostname}")
            except socket.herror as e:
                self.logger.warning(f"Resolução reversa básica falhou: {str(e)}")
            
            # Tentar resolução DNS reversa mais detalhada
            try:
                addr = dns.reversename.from_address(ip)
                registros_ptr = dns.resolver.resolve(addr, 'PTR')
                
                for rdata in registros_ptr:
                    hostname = str(rdata).rstrip('.')
                    if hostname not in dados['dominios_resolvidos']:
                        dados['dominios_resolvidos'].append(hostname)
                        
            except Exception as e:
                self.logger.debug(f"Resolução PTR falhou: {str(e)}")
            
            # Informações adicionais
            dados['informacoes_adicionais'] = {
                'ip_validado': True,
                'total_dominios_encontrados': len(dados['dominios_resolvidos']),
                'possui_resolucao_reversa': len(dados['dominios_resolvidos']) > 0
            }
            
        except Exception as e:
            raise Exception(f"Falha na resolução reversa: {str(e)}")
        
        return dados
    
    def gerar_resumo(self, resultado: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera resumo dos resultados de resolução DNS
        Args:
            resultado (Dict): Resultado da resolução DNS
        Returns:
            Dict[str, Any]: Resumo formatado
        """
        if not resultado.get('sucesso'):
            return {
                'status': 'falha',
                'erro': resultado.get('erro', 'Erro desconhecido'),
                'alvo': resultado.get('alvo_original', 'N/A')
            }
        
        dados = resultado.get('dados', {})
        tipo_alvo = resultado.get('tipo_alvo', 'desconhecido')
        
        resumo = {
            'status': 'sucesso',
            'alvo_original': resultado.get('alvo_original'),
            'tipo_alvo': tipo_alvo,
            'timestamp': resultado.get('timestamp_inicio')
        }
        
        if tipo_alvo == 'dominio':
            resumo.update({
                'ip_principal': dados.get('ip_principal', 'N/A'),
                'total_ips': len(dados.get('ips_resolvidos', [])),
                'ips_encontrados': dados.get('ips_resolvidos', []),
                'registros_dns': list(dados.get('registros_dns', {}).keys()),
                'possui_ipv6': 'AAAA' in dados.get('registros_dns', {}),
                'possui_mx': 'MX' in dados.get('registros_dns', {}),
                'possui_cname': 'CNAME' in dados.get('registros_dns', {})
            })
        else:  # IP
            resumo.update({
                'ip': dados.get('ip'),
                'hostname_principal': dados.get('hostname_principal', 'N/A'),
                'total_dominios': len(dados.get('dominios_resolvidos', [])),
                'dominios_encontrados': dados.get('dominios_resolvidos', []),
                'possui_resolucao_reversa': len(dados.get('dominios_resolvidos', [])) > 0
            })
        
        return resumo


if __name__ == "__main__":
    # Teste do módulo
    resolver = ResolucaoDNS()
    
    # Teste com domínio
    print("=== Teste com Domínio ===")
    resultado_dominio = resolver.resolver_dns("google.com")
    print(f"Sucesso: {resultado_dominio['sucesso']}")
    if resultado_dominio['sucesso']:
        resumo = resolver.gerar_resumo(resultado_dominio)
        print(f"IP Principal: {resumo.get('ip_principal', 'N/A')}")
        print(f"Total IPs: {resumo.get('total_ips', 0)}")
    
    # Teste com IP
    print("\n=== Teste com IP ===")
    resultado_ip = resolver.resolver_dns("8.8.8.8")
    print(f"Sucesso: {resultado_ip['sucesso']}")
    if resultado_ip['sucesso']:
        resumo = resolver.gerar_resumo(resultado_ip)
        print(f"Hostname: {resumo.get('hostname_principal', 'N/A')}")
        print(f"Total Domínios: {resumo.get('total_dominios', 0)}")