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

if ($Install) {
    $pip = Join-Path $VenvDir 'Scripts\pip.exe'
    Write-Host "Atualizando pip..."
    & $pip install --upgrade pip

    if (Test-Path "requirements.txt") {
        Write-Host "Instalando dependências de requirements.txt..."
        & $pip install -r requirements.txt
    } else {
        Write-Host "requirements.txt não encontrado — instalando conjunto mínimo de dependências..."
        $pkgs = @('requests','pyyaml')
        if ($WithAI) { $pkgs += 'google-generativeai' }
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
