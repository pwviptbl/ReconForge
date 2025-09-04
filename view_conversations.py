#!/usr/bin/env python3
"""
Visualizador de conversas do VarreduraIA (formato texto simples)
"""

import os
import sys
from pathlib import Path
from utils.simple_ai_logger import SimpleAILogger


def list_conversations():
    """Lista todas as conversas disponíveis"""
    logger = SimpleAILogger()
    sessions = logger.get_all_sessions()
    
    if not sessions:
        print("❌ Nenhuma conversa encontrada.")
        return
    
    print("📜 CONVERSAS DISPONÍVEIS:")
    print("=" * 50)
    
    for i, session in enumerate(sessions, 1):
        # Extrair informações do nome da sessão
        parts = session.replace("conversation_", "").split("_")
        if len(parts) >= 3:
            target = parts[0].replace("_", ".")
            date = parts[1] if len(parts[1]) == 8 else "data_desconhecida"
            time = parts[2] if len(parts[2]) == 6 else "hora_desconhecida"
            
            # Formatar data e hora
            if date != "data_desconhecida":
                formatted_date = f"{date[6:8]}/{date[4:6]}/{date[0:4]}"
            else:
                formatted_date = date
                
            if time != "hora_desconhecida":
                formatted_time = f"{time[0:2]}:{time[2:4]}:{time[4:6]}"
            else:
                formatted_time = time
            
            print(f"{i:2d}. {target} - {formatted_date} {formatted_time}")
        else:
            print(f"{i:2d}. {session}")


def view_conversation(session_id: str):
    """Visualiza uma conversa específica"""
    logger = SimpleAILogger()
    content = logger.read_session(session_id)
    
    if "não encontrada" in content:
        print(f"❌ {content}")
        return
    
    print("\n" + "=" * 70)
    print(content)
    print("=" * 70)


def main():
    if len(sys.argv) < 2:
        print("📖 USO:")
        print("  python view_conversations.py list               # Lista conversas")
        print("  python view_conversations.py view <numero>      # Visualiza conversa")
        print("  python view_conversations.py view <session_id>  # Visualiza por ID")
        return
    
    command = sys.argv[1]
    
    if command == "list":
        list_conversations()
        
    elif command == "view":
        if len(sys.argv) < 3:
            print("❌ Especifique o número ou ID da conversa")
            return
        
        target = sys.argv[2]
        logger = SimpleAILogger()
        sessions = logger.get_all_sessions()
        
        # Se for um número, converter para session_id
        if target.isdigit():
            index = int(target) - 1
            if 0 <= index < len(sessions):
                session_id = sessions[index]
            else:
                print(f"❌ Número inválido. Use de 1 a {len(sessions)}")
                return
        else:
            session_id = target
        
        view_conversation(session_id)
        
    else:
        print(f"❌ Comando desconhecido: {command}")
        print("Use 'list' ou 'view'")


if __name__ == "__main__":
    main()
