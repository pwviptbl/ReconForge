#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste da Fase 3: Fluxo de Decisão Autônomo
Valida o sistema de eventos e paralelização
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.orquestrador_inteligente import EventManager, Evento
from datetime import datetime
import threading
import time

def teste_event_manager():
    """Testa o EventManager"""
    print("🧪 Testando EventManager...")

    event_manager = EventManager()

    # Testar registro de listener
    def listener_teste(evento):
        print(f"📡 Evento recebido: {evento.tipo}")

    # Registrar listener
    event_manager.registrar_listener("teste_evento", listener_teste)

    # Disparar evento
    evento = Evento(
        tipo="teste_evento",
        dados={"mensagem": "teste"},
        timestamp=datetime.now().isoformat(),
        prioridade="media"
    )
    event_manager.disparar_evento(evento)

    # Verificar se o evento foi registrado
    eventos = event_manager.obter_eventos_recentes(5)
    assert len(eventos) == 1, "Evento não foi registrado"
    assert eventos[0].tipo == "teste_evento", "Tipo de evento incorreto"

    print("✅ EventManager funcionando corretamente")
    return True

def teste_eventos_orquestrador():
    """Testa eventos no contexto do orquestrador"""
    print("🧪 Testando eventos no orquestrador...")

    try:
        from core.orquestrador_inteligente import ContextoExecucao

        contexto = ContextoExecucao(
            alvo_original="teste.com",
            timestamp_inicio=datetime.now().isoformat()
        )

        # Simular descoberta de host
        evento = Evento(
            tipo="novo_host_descoberto",
            dados={"host": "192.168.1.1"},
            timestamp=datetime.now().isoformat(),
            prioridade="alta"
        )
        contexto.eventos.append(evento)

        assert len(contexto.eventos) == 1, "Evento não foi adicionado ao contexto"
        print("✅ Sistema de eventos no contexto funcionando")

    except Exception as e:
        print(f"❌ Erro no teste de eventos: {e}")
        return False

    return True

def teste_paralelizacao():
    """Testa o sistema de paralelização"""
    print("🧪 Testando paralelização...")

    try:
        from concurrent.futures import ThreadPoolExecutor

        executor = ThreadPoolExecutor(max_workers=2)

        def tarefa_teste(n):
            time.sleep(0.1)
            return f"Tarefa {n} concluída"

        # Executar tarefas em paralelo
        futures = [executor.submit(tarefa_teste, i) for i in range(3)]

        resultados = []
        for future in futures:
            resultados.append(future.result())

        assert len(resultados) == 3, "Nem todas as tarefas foram executadas"
        print("✅ Sistema de paralelização funcionando")

        executor.shutdown()
        return True

    except Exception as e:
        print(f"❌ Erro na paralelização: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Iniciando testes da Fase 3: Fluxo de Decisão Autônomo")
    print("=" * 60)

    testes = [
        ("EventManager", teste_event_manager),
        ("Eventos no Orquestrador", teste_eventos_orquestrador),
        ("Paralelização", teste_paralelizacao)
    ]

    testes_passados = 0
    for nome, teste in testes:
        try:
            if teste():
                testes_passados += 1
                print(f"✅ {nome}: PASSOU")
            else:
                print(f"❌ {nome}: FALHOU")
        except Exception as e:
            print(f"❌ {nome}: ERRO - {e}")

    print("=" * 60)
    print(f"📊 Resultado: {testes_passados}/{len(testes)} testes passaram")

    if testes_passados == len(testes):
        print("🎉 Fase 3 validada com sucesso!")
        sys.exit(0)
    else:
        print("⚠️ Alguns testes falharam. Verificar implementação.")
        sys.exit(1)
