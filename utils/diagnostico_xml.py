#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para diagnosticar problemas XML do Nmap
"""

import sys
import os
from pathlib import Path

# Adicionar o diretório raiz ao path
sys.path.append(str(Path(__file__).parent.parent))

from modulos.varredura_nmap import VarreduraNmap
from utils.logger import obter_logger

def diagnosticar_xml():
    """Diagnostica problemas com XML do Nmap"""
    logger = obter_logger('DiagnosticoXML')
    
    logger.info("=== DIAGNÓSTICO DE PROBLEMAS XML DO NMAP ===")
    
    # Criar instância do VarreduraNmap
    varredura = VarreduraNmap()
    
    # Verificar se Nmap está disponível
    if not varredura.verificar_nmap():
        logger.error("❌ Nmap não está disponível")
        return
    
    logger.info("✅ Nmap está disponível")
    
    # Teste 1: Comando muito simples
    logger.info("\n1️⃣ Testando comando Nmap simples...")
    resultado = varredura.testar_nmap_xml('127.0.0.1')
    
    if resultado.get('sucesso'):
        logger.info("✅ Teste simples passou - XML gerado corretamente")
    else:
        logger.error("❌ Teste simples falhou")
        logger.error(f"Erro: {resultado.get('erro')}")
        
        # Mostrar diagnóstico detalhado
        diagnostico = resultado.get('diagnostico_xml')
        if diagnostico:
            logger.info("\n🔍 Diagnóstico detalhado:")
            logger.info(f"Arquivo existe: {diagnostico['arquivo_existe']}")
            logger.info(f"Tamanho: {diagnostico['tamanho_bytes']} bytes")
            logger.info(f"XML válido: {diagnostico['xml_valido']}")
            logger.info(f"Nmap válido: {diagnostico['nmap_valido']}")
            
            if diagnostico['problemas']:
                logger.info("Problemas encontrados:")
                for problema in diagnostico['problemas']:
                    logger.info(f"  - {problema}")
            
            if diagnostico['sugestoes']:
                logger.info("Sugestões:")
                for sugestao in diagnostico['sugestoes']:
                    logger.info(f"  - {sugestao}")
    
    # Teste 2: Verificar saída do Nmap diretamente
    logger.info("\n2️⃣ Testando Nmap diretamente no terminal...")
    
    import subprocess
    import tempfile
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            arquivo_xml = temp_file.name
        
        comando = ['nmap', '-p', '80', '-sT', '127.0.0.1', '-oX', arquivo_xml]
        logger.info(f"Comando: {' '.join(comando)}")
        
        processo = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        logger.info(f"Código de saída: {processo.returncode}")
        
        if processo.stdout:
            logger.info(f"STDOUT: {processo.stdout}")
        
        if processo.stderr:
            logger.info(f"STDERR: {processo.stderr}")
        
        # Verificar arquivo XML
        if os.path.exists(arquivo_xml):
            tamanho = os.path.getsize(arquivo_xml)
            logger.info(f"✅ Arquivo XML criado: {tamanho} bytes")
            
            if tamanho > 0:
                with open(arquivo_xml, 'r') as f:
                    conteudo = f.read()
                logger.info(f"Primeiros 200 caracteres do XML:")
                logger.info(conteudo[:200])
            else:
                logger.error("❌ Arquivo XML está vazio")
        else:
            logger.error("❌ Arquivo XML não foi criado")
        
        # Limpar arquivo temporário
        try:
            os.unlink(arquivo_xml)
        except:
            pass
            
    except Exception as e:
        logger.error(f"Erro no teste direto: {str(e)}")
    
    # Teste 3: Verificar permissões e ambiente
    logger.info("\n3️⃣ Verificando ambiente...")
    
    # Verificar diretório temporário
    import tempfile
    temp_dir = tempfile.gettempdir()
    logger.info(f"Diretório temporário: {temp_dir}")
    
    if os.access(temp_dir, os.W_OK):
        logger.info("✅ Diretório temporário tem permissão de escrita")
    else:
        logger.error("❌ Diretório temporário não tem permissão de escrita")
    
    # Verificar espaço em disco
    try:
        statvfs = os.statvfs(temp_dir)
        espaco_livre = statvfs.f_frsize * statvfs.f_avail
        logger.info(f"Espaço livre: {espaco_livre / (1024*1024):.1f} MB")
    except:
        logger.warning("Não foi possível verificar espaço em disco")
    
    # Verificar versão do Nmap
    try:
        resultado_versao = subprocess.run(
            ['nmap', '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if resultado_versao.returncode == 0:
            logger.info(f"Versão do Nmap: {resultado_versao.stdout.split()[1]}")
        else:
            logger.warning("Não foi possível obter versão do Nmap")
    except:
        logger.warning("Erro ao verificar versão do Nmap")

if __name__ == "__main__":
    diagnosticar_xml()
