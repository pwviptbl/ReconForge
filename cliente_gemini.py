#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de conexão com a API do Gemini
Conecta ao modelo gemini-2.5-pro usando a chave API fornecida
"""

import os
import sys
import logging
from typing import Optional, Dict, Any
import google.generativeai as genai

class ClienteGemini:
    """Cliente para conexão com a API do Gemini"""
    
    def __init__(self, chave_api: str = None, modelo: str = "gemini-2.5-pro"):
        """
        Inicializa o cliente Gemini
        
        Args:
            chave_api (str): Chave da API do Gemini
            modelo (str): Nome do modelo a ser utilizado
        """
        self.chave_api = chave_api or "AIzaSyDvgL5ssyTOQk5x-9Fl7tLV3hy1H62Q2UQ"
        self.modelo_nome = modelo
        self.modelo = None
        self.configurar_logging()
        
    def configurar_logging(self):
        """Configura o sistema de logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('gemini_cliente.log', encoding='utf-8')
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def conectar(self) -> bool:
        """
        Estabelece conexão com a API do Gemini
        
        Returns:
            bool: True se a conexão foi bem-sucedida, False caso contrário
        """
        try:
            # Configurar a chave API
            genai.configure(api_key=self.chave_api)
            
            # Inicializar o modelo
            self.modelo = genai.GenerativeModel(self.modelo_nome)
            
            # Testar a conexão
            resposta_teste = self.modelo.generate_content("Olá, você está funcionando?")
            
            self.logger.info(f"Conexão estabelecida com sucesso com o modelo {self.modelo_nome}")
            self.logger.info(f"Resposta de teste: {resposta_teste.text}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao conectar com a API do Gemini: {str(e)}")
            return False
    
    def enviar_mensagem(self, mensagem: str) -> Optional[str]:
        """
        Envia uma mensagem para o modelo Gemini
        
        Args:
            mensagem (str): Mensagem a ser enviada
            
        Returns:
            Optional[str]: Resposta do modelo ou None em caso de erro
        """
        if not self.modelo:
            self.logger.error("Modelo não inicializado. Execute conectar() primeiro.")
            return None
            
        try:
            resposta = self.modelo.generate_content(mensagem)
            self.logger.info(f"Mensagem enviada: {mensagem[:50]}...")
            return resposta.text
            
        except Exception as e:
            self.logger.error(f"Erro ao enviar mensagem: {str(e)}")
            return None
    
    def chat_interativo(self):
        """Inicia um chat interativo com o modelo"""
        print("=== Chat Interativo com Gemini ===")
        print("Digite 'sair' para encerrar o chat")
        print("-" * 40)
        
        while True:
            try:
                mensagem = input("\nVocê: ").strip()
                
                if mensagem.lower() in ['sair', 'exit', 'quit']:
                    print("Encerrando chat...")
                    break
                
                if not mensagem:
                    continue
                
                resposta = self.enviar_mensagem(mensagem)
                if resposta:
                    print(f"\nGemini: {resposta}")
                else:
                    print("Erro ao obter resposta. Tente novamente.")
                    
            except KeyboardInterrupt:
                print("\nChat interrompido pelo usuário.")
                break
            except Exception as e:
                print(f"Erro inesperado: {str(e)}")
    
    def obter_informacoes_modelo(self) -> Dict[str, Any]:
        """
        Obtém informações sobre o modelo configurado
        
        Returns:
            Dict[str, Any]: Informações do modelo
        """
        try:
            modelos_disponiveis = list(genai.list_models())
            modelo_atual = None
            
            for modelo in modelos_disponiveis:
                if self.modelo_nome in modelo.name:
                    modelo_atual = modelo
                    break
            
            if modelo_atual:
                return {
                    "nome": modelo_atual.name,
                    "versao": modelo_atual.version,
                    "descricao": modelo_atual.description,
                    "limites_entrada": modelo_atual.input_token_limit,
                    "limites_saida": modelo_atual.output_token_limit,
                    "metodos_suportados": modelo_atual.supported_generation_methods
                }
            else:
                return {"erro": f"Modelo {self.modelo_nome} não encontrado"}
                
        except Exception as e:
            return {"erro": f"Erro ao obter informações do modelo: {str(e)}"}


def main():
    """Função principal para demonstração do cliente"""
    print("=== Cliente Gemini ===")
    print("Iniciando conexão com a API...")
    
    # Criar instância do cliente
    cliente = ClienteGemini()
    
    # Conectar à API
    if cliente.conectar():
        print("✓ Conexão estabelecida com sucesso!")
        
        # Exibir informações do modelo
        info_modelo = cliente.obter_informacoes_modelo()
        if "erro" not in info_modelo:
            print(f"\n--- Informações do Modelo ---")
            for chave, valor in info_modelo.items():
                print(f"{chave.capitalize()}: {valor}")
        
        # Exemplo de uso
        print("\n--- Exemplo de Uso ---")
        resposta = cliente.enviar_mensagem("Explique em uma frase o que é inteligência artificial.")
        if resposta:
            print(f"Resposta: {resposta}")
        
        # Iniciar chat interativo
        escolha = input("\nDeseja iniciar o chat interativo? (s/n): ").strip().lower()
        if escolha in ['s', 'sim', 'y', 'yes']:
            cliente.chat_interativo()
    else:
        print("✗ Falha ao conectar com a API do Gemini")
        sys.exit(1)


if __name__ == "__main__":
    main()