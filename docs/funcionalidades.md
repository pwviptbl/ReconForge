# Funcionalidades atuais

O fluxo atual foi reduzido para caber em uma operacao simples:

1. descobrir superficie
2. mapear entradas
3. testar o que faz sentido
4. gerar relatorio

## Modos de uso

### `web-map`

Para homologacao e mapeamento gentil de entradas web:

- coleta links, formularios e botoes
- preenche campos com heuristica segura
- observa requests reais e usa a rede como fonte de verdade
- registra GET, POST, multipart, uploads e interacoes sem request

### `web-test`

Tudo do `web-map`, seguido de scanners request-based:

- XSS
- LFI
- SSRF
- SSTI
- IDOR
- Open Redirect
- Header Injection
- Nuclei

### `infra`

Foco em servicos e exposicao:

- portas abertas
- servicos detectados
- SSL/TLS
- firewall/WAF
- exposicao de portas sensiveis
- policy SSH

## Web flow mapping

O `WebFlowMapperPlugin` virou o componente central da descoberta web.

Ele entrega:

- `forms`
- `request_nodes`
- `interactions`
- `parameters`

Esses dados alimentam os scanners posteriores. O scanner nao depende mais so do DOM; ele prioriza a request observada.

## Healthcheck

Antes de rodar um perfil, voce pode validar o ambiente:

```bash
./run.sh --healthcheck
```

Isso mostra:

- Python ativo
- modulo `playwright`
- plugins carregados
- plugins desativados e motivo
- disponibilidade dos perfis

## Mostrar rotas e parametros

Depois do run:

```bash
./run.sh --show-web-map 50
```

Saida esperada:

- formularios detectados
- requests observadas
- buckets de parametros
- acao UI associada

## Personalizacao

O projeto continua permitindo ligacao e desligamento de plugins por YAML. Isso cobre os casos especiais sem complicar o caminho padrao.

Recomendacao pratica:

- use perfil por default
- ajuste YAML apenas quando tiver necessidade real
- deixe `DirectoryScannerPlugin` fora do fluxo normal
