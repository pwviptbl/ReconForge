# Configuração do Sistema

## Arquivo de Configuração

O sistema utiliza um único arquivo de configuração em formato YAML:

- **`config/default.yaml`** - Arquivo principal de configuração (não versionado)
- **`config/default.yaml.example`** - Template/exemplo (versionado)

## Configuração Inicial

1. Copie o arquivo de exemplo:
```bash
cp config/default.yaml.example config/default.yaml
```

2. Edite o arquivo `config/default.yaml` e configure:
   - Sua chave API do Gemini
   - Caminhos dos binários das ferramentas
   - Outras preferências

## Obtendo a Chave API do Gemini

1. Acesse: https://aistudio.google.com/app/apikey
2. Faça login com sua conta Google
3. Clique em "Create API Key"
4. Copie a chave gerada
5. Cole no campo `api.gemini.chave_api` do arquivo `config/default.yaml`

## Estrutura da Configuração

O arquivo YAML contém as seguintes seções:

- **api**: Configurações da API Gemini
- **nmap**: Configurações do Nmap
- **feroxbuster**: Configurações do Feroxbuster
- **sqlmap**: Configurações do SQLMap
- **banco_dados**: Configurações de persistência
- **logging**: Configurações de log
- **relatorios**: Configurações de relatórios
- **seguranca**: Configurações de segurança
- **openvas**: Configurações do OpenVAS/GVM
- **proxy**: Configurações de proxy
- **desenvolvimento**: Configurações de desenvolvimento
- **notificacoes**: Configurações de notificações
- **cache**: Configurações de cache
- **backup**: Configurações de backup

## Migração do .env

## Segurança

 **IMPORTANTE**: O arquivo `config/default.yaml` contém informações sensíveis (chaves API) e está incluído no `.gitignore`. **NUNCA** faça commit deste arquivo.
