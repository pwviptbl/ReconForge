<#
PowerShell script para criar um virtualenv e opcionalmente instalar dependências
Uso: .\create_venv.ps1 [-Install] [-WithAI] [-Name VENV_NAME]

Opções:
  -Install    Instala dependências (requer internet)
  -WithAI     Instala google-generativeai além das dependências padrão
  -Name       Nome/pasta do virtualenv (default: .venv)
#>

param(
    [switch]$Install,
    [switch]$WithAI,
    [string]$Name = '.venv'
)

$VenvDir = $Name

Write-Host "Criando virtualenv em $VenvDir..."
python -m venv $VenvDir

Write-Host "Para ativar no PowerShell: .\$VenvDir\Scripts\Activate.ps1"
Write-Host "Para ativar no cmd.exe: $VenvDir\Scripts\activate.bat"

# Copiar configuração de exemplo se necessário
$example = 'config\default.exemple.yaml'
$target = 'config\default.yaml'
if (-not (Test-Path $target) -and (Test-Path $example)) {
    New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
    Copy-Item -Path $example -Destination $target -Force
    Write-Host "Arquivo de configuração padrão criado: $target (copiado de $example)"
}

if ($Install) {
    $pip = Join-Path $VenvDir 'Scripts\pip.exe'
    Write-Host "Atualizando pip..."
    & $pip install --upgrade pip

    if (Test-Path "requirements.txt") {
        Write-Host "Instalando dependências de requirements.txt..."
        & $pip install -r requirements.txt
    } else {
        Write-Host "requirements.txt não encontrado — instalando conjunto mínimo de dependências..."
    # Incluir google-generativeai por padrão (a aplicação usa esta biblioteca)
    $pkgs = @('requests','pyyaml','google-generativeai')
        Write-Host "Instalando: $($pkgs -join ', ')"
        & $pip install $pkgs
    }
    Write-Host "Dependências instaladas. Ative o venv conforme acima."
} else {
    if ($WithAI) {
        Write-Host "Aviso: -WithAI foi passado mas sem -Install não haverá instalação. Use -Install -WithAI para instalar google-generativeai."
    }
}

Write-Host "Pronto. Para sair do venv: deactivate (no PowerShell também funciona)"
