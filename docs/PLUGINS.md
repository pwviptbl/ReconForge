# Plugins do ReconForge

O projeto foi simplificado para operar com um unico fluxo de execucao e duas formas de ajuste:

- por perfil, que e o caminho recomendado
- por habilitacao/desabilitacao de plugins, quando voce quer personalizar

Se um plugin nao aparece nesta pagina, ele nao faz mais parte do fluxo atual.

## Perfis recomendados

Use perfis antes de sair montando listas manuais.

- `web-map`: mapeia rotas, formularios, requests observadas e parametros
- `web-test`: faz o `web-map` e depois executa os scanners HTTP request-based
- `infra`: foca em portas, servicos, SSL e exposicao de infraestrutura

Comandos:

```bash
./run.sh alvo --profile web-map
./run.sh alvo --profile web-test
./run.sh alvo --profile infra
./run.sh --healthcheck
./run.sh --show-web-map 50
```

## Plugins ativos

### Recon e descoberta

- `PortScannerPlugin`
- `NmapScannerPlugin`
- `DNSResolverPlugin`
- `SubfinderPlugin`
- `ReconnaissancePlugin`
- `NetworkMapperPlugin`
- `TrafficAnalyzerPlugin`
- `FirewallDetectorPlugin`
- `PortExposureAudit`
- `SSHPolicyCheck`

### Web

- `WhatWebScannerPlugin`
- `TechnologyDetectorPlugin`
- `GauCollectorPlugin`
- `KatanaCrawlerPlugin`
- `WebFlowMapperPlugin`
- `HeaderAnalyzerPlugin`
- `DirectoryScannerPlugin`

### Vulnerabilidades

- `NucleiScannerPlugin`
- `XSSScannerPlugin`
- `LFIScannerPlugin`
- `SSRFScannerPlugin`
- `IDORScannerPlugin`
- `SSTIScannerPlugin`
- `OpenRedirectScannerPlugin`
- `HeaderInjectionScannerPlugin`
- `SSLAnalyzerPlugin`

### Inteligencia de exploit

- `ExploitSearcherPlugin`

## O que fica fora do caminho padrao

Nem tudo precisa rodar sempre.

- `DirectoryScannerPlugin`: util para fuzzing, mas agressivo; use por escolha explicita
- `ReconnaissancePlugin`: util para OSINT e contexto amplo, nao para toda auditoria web
- `TechnologyDetectorPlugin`: fallback quando o `WhatWebScannerPlugin` nao cobre bem
- `NetworkMapperPlugin`, `TrafficAnalyzerPlugin`, `FirewallDetectorPlugin`: mais uteis em perfil infra do que em perfil web

## Habilitar ou desabilitar

O ponto central continua sendo o YAML. Isso mantem a ferramenta simples: o default funciona, e voce personaliza so quando precisar.

Exemplo:

```yaml
plugins:
  enabled:
    DirectoryScannerPlugin: false
    WebFlowMapperPlugin: true
    NucleiScannerPlugin: true
```

Configuracoes especificas por plugin continuam em `plugins.config`.

Exemplo:

```yaml
plugins:
  config:
    WebFlowMapperPlugin:
      max_depth: 3
      max_pages: 30
      max_actions_per_page: 10
```

## Dependencias e healthcheck

Plugins podem ser desativados automaticamente quando falta dependencia de sistema ou modulo Python. O jeito certo de verificar isso agora e:

```bash
./run.sh --healthcheck
```

O healthcheck mostra:

- Python em uso
- se `playwright` esta importavel
- plugins carregados
- plugins desativados e o motivo
- quais perfis estao prontos ou bloqueados

## Web map

Quando o `WebFlowMapperPlugin` roda, o mapeamento de entradas fica disponivel em tres lugares:

- resumo do pipeline
- relatorio final
- comando `--show-web-map`

Exemplo:

```bash
./run.sh hom.nfse.charqueadas.rs.gov.br --profile web-map
./run.sh --show-web-map 50
```
