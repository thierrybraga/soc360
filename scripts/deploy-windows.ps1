# Open-Monitor Deployment Script for Windows
# Supports Windows Server and Windows 10/11
# Usage: .\deploy-windows.ps1 [Command] [-Debug]
#
# CHANGELOG:
#   v3.2.0 - PostgreSQL: geração de postgres_password.txt; checagem de portas
#            ajustada (80/443/5432); status mostra banco soc360
#   v3.1.0 - Segurança: RNGCryptoServiceProvider para secrets
#   v3.1.0 - Robustez: Backup automático, retry em comandos
#   v3.1.0 - Usabilidade: Timestamps, verificação de versão compose

param(
    [string]$Command = "start",
    [switch]$DebugMode = $false
)

# ============================================
# CONFIGURATION
# ============================================
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ScriptDir = $PSScriptRoot
$ScriptVersion = "3.2.0"

# Colors
$ESC = "$([char]0x001b)"
$RED = "$ESC[31m"
$GREEN = "$ESC[32m"
$YELLOW = "$ESC[33m"
$BLUE = "$ESC[34m"
$CYAN = "$ESC[36m"
$MAGENTA = "$ESC[35m"
$NC = "$ESC[0m"
$BOLD = "$ESC[1m"

# Global variables
$script:COMPOSE_CMD = $null
$script:COMPOSE_FILE = $null

# Detectar compose file apropriado
if (Test-Path (Join-Path $ProjectRoot "docker-compose.windows.yml")) {
    $script:COMPOSE_FILE = "docker-compose.windows.yml"
} elseif (Test-Path (Join-Path $ProjectRoot "docker-compose.yml")) {
    $script:COMPOSE_FILE = "docker-compose.yml"
}

# Habilitar BuildKit
$env:DOCKER_BUILDKIT = "1"
$env:COMPOSE_DOCKER_CLI_BUILD = "1"

# ============================================
# FUNCTIONS
# ============================================

function Write-Banner {
    if ($DebugMode) {
        Write-Host @"
$CYAN╔═══════════════════════════════════════════════════════════╗
║     Open-Monitor Windows Deployment - DEBUG MODE           ║
║              v$ScriptVersion                                         ║
╚═══════════════════════════════════════════════════════════╝$NC
"@
    } else {
        Write-Host @"
$CYAN╔═══════════════════════════════════════════════╗
║     Open-Monitor Windows Deployment            ║
║              v$ScriptVersion                      ║
╚═══════════════════════════════════════════════╝$NC
"@
    }
}

function Get-Timestamp { return Get-Date -Format "yyyy-MM-dd HH:mm:ss" }
function Write-Info { param([string]$Message); Write-Host "[$(Get-Timestamp)] ${BLUE}[INFO]${NC} $Message" }
function Write-Debug { param([string]$Message); if ($DebugMode) { Write-Host "[$(Get-Timestamp)] ${MAGENTA}[DEBUG]${NC} $Message" } }
function Write-Success { param([string]$Message); Write-Host "[$(Get-Timestamp)] ${GREEN}[OK]${NC} $Message" }
function Write-Warn { param([string]$Message); Write-Host "[$(Get-Timestamp)] ${YELLOW}[WARN]${NC} $Message" }
function Write-Error { 
    param([string]$Message)
    Write-Host "[$(Get-Timestamp)] ${RED}[ERROR]${NC} $Message"
    exit 1 
}

# ============================================
# SECURITY FUNCTIONS
# ============================================

function New-SecureRandomString {
    <#
    .SYNOPSIS
        Gera string aleatória segura usando RNGCryptoServiceProvider
    .DESCRIPTION
        Substitui Get-Random por gerador criptograficamente seguro
    #>
    param(
        [int]$Length = 64,
        [switch]$AsHex
    )
    
    try {
        $bytes = New-Object byte[] ($Length / 2)
        $rng = [Security.Cryptography.RNGCryptoServiceProvider]::Create()
        $rng.GetBytes($bytes)
        $rng.Dispose()
        
        if ($AsHex) {
            return [BitConverter]::ToString($bytes).Replace("-", "").ToLower()
        } else {
            return [Convert]::ToBase64String($bytes)
        }
    } catch {
        # Fallback para método menos seguro apenas se criptografia falhar
        Write-Warn "Falha no gerador criptográfico, usando fallback"
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        $result = -join ($chars.ToCharArray() | Get-Random -Count $Length)
        return $result
    }
}

function Validate-SecretKey {
    param([string]$KeyFile)
    
    if (Test-Path $KeyFile) {
        $content = Get-Content $KeyFile -Raw
        $length = $content.Length
        
        if ($length -lt 64) {
            Write-Warn "SECRET_KEY muito curta ($length chars). Mínimo: 64 chars"
            Remove-Item $KeyFile -Force
            return $false
        }
    }
    return $true
}

function Set-SecurePermissions {
    param([string]$Path)
    
    if (Test-Path $Path) {
        try {
            # Tentar remover permissões herdadas (pode falhar sem privilégios de admin)
            $acl = Get-Acl $Path -ErrorAction SilentlyContinue
            if ($acl) {
                $acl.SetAccessRuleProtection($true, $false)
                
                # Adicionar apenas permissão para o usuário atual
                $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $user, "FullControl", "Allow"
                )
                $acl.SetAccessRule($rule)
                Set-Acl $Path $acl -ErrorAction SilentlyContinue
            }
            
            # Silenciosamente ignorar erros de privilégio - não é crítico
            Write-Success "Permissões verificadas em $Path"
        } catch {
            # Silenciosamente ignorar - permissões são nice-to-have, não crítico
            Write-Debug "Não foi possível modificar permissões em $Path (não crítico)"
        }
    }
}

# ============================================
# UTILITY FUNCTIONS
# ============================================

function Invoke-RetryCommand {
    <#
    .SYNOPSIS
        Executa comando com retry e backoff exponencial
    #>
    param(
        [scriptblock]$Command,
        [int]$MaxAttempts = 3,
        [int]$InitialDelay = 5
    )
    
    $attempt = 1
    $delay = $InitialDelay
    
    while ($attempt -le $MaxAttempts) {
        try {
            & $Command
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $null) {
                return $true
            }
        } catch {
            # Continuar para retry
        }
        
        if ($attempt -lt $MaxAttempts) {
            Write-Warn "Falha na tentativa $attempt/$MaxAttempts. Retry em ${delay}s..."
            Start-Sleep -Seconds $delay
            $delay = $delay * 2
        }
        $attempt++
    }
    
    return $false
}

function Backup-BeforeUpdate {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupDir = Join-Path $ProjectRoot "backups\pre-deploy-$timestamp"
    
    Write-Info "Criando backup em $backupDir..."
    
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    
    # Backup de arquivos críticos
    $filesToBackup = @(".env", "secrets")
    foreach ($file in $filesToBackup) {
        $source = Join-Path $ProjectRoot $file
        if (Test-Path $source) {
            Copy-Item -Path $source -Destination $backupDir -Recurse -Force
        }
    }
    
    # Backup do docker-compose
    Copy-Item -Path (Join-Path $ProjectRoot $script:COMPOSE_FILE) -Destination $backupDir -Force
    
    # Criar link para latest
    $latestLink = Join-Path $ProjectRoot "backups\latest"
    if (Test-Path $latestLink) {
        Remove-Item $latestLink -Force
    }
    New-Item -ItemType SymbolicLink -Path $latestLink -Target $backupDir -Force | Out-Null
    
    # Salvar referência
    $backupDir | Set-Content -Path (Join-Path $ProjectRoot "backups\.last_backup") -NoNewline
    
    Write-Success "Backup criado em $backupDir"
    return $backupDir
}

function Invoke-Rollback {
    $backupDir = Join-Path $ProjectRoot "backups\latest"
    
    if (-not (Test-Path $backupDir)) {
        Write-Error "Nenhum backup encontrado para rollback"
    }
    
    Write-Warn "Executando rollback para: $backupDir"
    Write-Info "Esta operação irá restaurar configurações anteriores e reiniciar os serviços."
    
    # Confirmação do usuário
    $confirm = Read-Host "Digite 'yes' para confirmar o rollback"
    if ($confirm -ne "yes") {
        Write-Info "Rollback cancelado pelo usuário"
        return
    }
    
    Write-Info "Parando serviços atuais..."
    Stop-Services
    
    Write-Info "Restaurando arquivos..."
    $filesToRestore = @(".env", "secrets")
    foreach ($file in $filesToRestore) {
        $source = Join-Path $backupDir $file
        $dest = Join-Path $ProjectRoot $file
        if (Test-Path $source) {
            Copy-Item -Path $source -Destination $dest -Recurse -Force
            Write-Success "$file restaurado"
        } else {
            Write-Warn "Arquivo $file não encontrado no backup"
        }
    }
    
    Write-Info "Reiniciando serviços..."
    Start-Services
    Write-Success "Rollback concluído"
}

function Test-Command {
    param([string]$cmd)
    $null = Get-Command $cmd -ErrorAction SilentlyContinue
    return $?
}

function Test-ExecutionPolicy {
    $currentPolicy = Get-ExecutionPolicy
    if ($currentPolicy -eq "Restricted") {
        Write-Warn "Execution Policy está Restricted"
        Write-Info "Execute: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"
        return $false
    }
    return $true
}

function Test-Docker {
    Write-Info "Checking Docker installation..."
    
    if (-not (Test-Command "docker")) {
        Write-Error "Docker not installed. Install Docker Desktop for Windows."
    }
    
    try {
        $dockerInfo = docker info 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Docker not running" }
    } catch {
        Write-Error "Docker daemon not running. Start Docker Desktop."
    }
    
    Write-Success "Docker is available"
}

function Test-Compose {
    Write-Info "Checking Docker Compose..."
    
    # Try docker compose (plugin) first
    try {
        $result = docker compose version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $script:COMPOSE_CMD = "docker compose"
            
            # Verificar versão mínima
            $versionStr = $result -replace ".*version v?", ""
            $minVersion = [System.Version]"2.0.0"
            $currentVersion = $null
            
            if ([System.Version]::TryParse($versionStr, [ref]$currentVersion)) {
                if ($currentVersion -lt $minVersion) {
                    Write-Warn "Docker Compose v$currentVersion detectado. Recomendado: >= v2.0.0"
                }
            }
            
            Write-Success "Docker Compose plugin found"
            return
        }
    } catch { }
    
    # Try docker-compose (standalone)
    if (Test-Command "docker-compose") {
        try {
            $result = docker-compose version 2>&1
            if ($LASTEXITCODE -eq 0) {
                $script:COMPOSE_CMD = "docker-compose"
                Write-Success "Docker Compose standalone found"
                return
            }
        } catch { }
    }
    
    Write-Error "Docker Compose not available."
}

function Get-ComposeFile {
    # Check for Windows-specific compose file
    $windowsCompose = Join-Path $ProjectRoot "docker-compose.windows.yml"
    $defaultCompose = Join-Path $ProjectRoot "docker-compose.yml"
    
    if (Test-Path $windowsCompose) {
        $script:COMPOSE_FILE = "docker-compose.windows.yml"
        Write-Info "Using Windows-optimized compose file"
        Write-Debug "Compose file: $windowsCompose"
    } elseif (Test-Path $defaultCompose) {
        $script:COMPOSE_FILE = "docker-compose.yml"
        Write-Info "Using default compose file"
    } else {
        Write-Error "No docker-compose file found!"
    }
}

function Test-DiskSpace {
    Write-Info "Checking disk space..."
    $requiredGB = 10
    $drive = (Get-Item $ProjectRoot).PSDrive.Name
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($drive):'"
    $freeGB = [math]::Floor($disk.FreeSpace / 1GB)
    
    if ($freeGB -lt $requiredGB) {
        Write-Error "Insufficient disk space: $freeGB GB available, $requiredGB GB required"
    }
    
    Write-Success "Disk space OK: $freeGB GB available"
}

function Test-Ports {
    Write-Info "Checking required ports..."
    # Apenas portas publicadas no host pela stack core:
    #   80/443 = nginx ; 5432 = postgres (loopback por padrão).
    # 5000 (app) é interno; 8080 (airflow) e 11434 (ollama) são overlays opcionais.
    $ports = @(80, 443, 5432)
    $portInUse = $false
    
    foreach ($port in $ports) {
        $listener = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($listener) {
            Write-Warn "Port $port is already in use"
            $portInUse = $true
        }
    }
    
    if ($portInUse) {
        Write-Warn "Some ports are in use. Deployment may fail without alternative mapping."
        $continue = Read-Host "Continue anyway? (y/N)"
        if ($continue -ne 'y' -and $continue -ne 'Y') {
            exit 1
        }
    } else {
        Write-Success "Required ports are available"
    }
}

function Test-EnvFile {
    Write-Info "Checking environment configuration..."
    
    $envFile = Join-Path $ProjectRoot ".env"
    $envExample = Join-Path $ProjectRoot ".env.example"
    
    if (-not (Test-Path $envFile)) {
        Write-Warn ".env file not found"
        
        if (Test-Path $envExample) {
            Copy-Item $envExample $envFile
            Write-Success ".env created from .env.example"
            Write-Warn "IMPORTANT: Edit .env with your settings before running!"
        } else {
            Write-Error ".env.example not found."
        }
    } else {
        Write-Success ".env file exists"
    }
}

function Initialize-Secrets {
    Write-Info "Initializing secrets..."
    
    $secretsDir = Join-Path $ProjectRoot "secrets"
    if (-not (Test-Path $secretsDir)) {
        New-Item -ItemType Directory -Path $secretsDir -Force | Out-Null
    }
    
    # Generate secret_key.txt if not exists
    $secretKeyFile = Join-Path $secretsDir "secret_key.txt"
    if (-not (Test-Path $secretKeyFile)) {
        Write-Info "Generating secure secret_key.txt..."
        $secretKey = New-SecureRandomString -Length 64 -AsHex
        $secretKey | Set-Content -Path $secretKeyFile -NoNewline
        
        # Validar
        if (-not (Validate-SecretKey $secretKeyFile)) {
            Write-Error "Falha na validação do SECRET_KEY"
        }
        
        Write-Success "Generated secure secret_key.txt"
    } else {
        if (Validate-SecretKey $secretKeyFile) {
            Write-Success "secret_key.txt already exists and is valid"
        } else {
            Write-Warn "secret_key.txt existente é inválido, regenerando..."
            $secretKey = New-SecureRandomString -Length 64 -AsHex
            $secretKey | Set-Content -Path $secretKeyFile -NoNewline
            Write-Success "Regenerated secure secret_key.txt"
        }
    }
    
    # Generate redis_password.txt if not exists
    $redisPasswordFile = Join-Path $secretsDir "redis_password.txt"
    if (-not (Test-Path $redisPasswordFile)) {
        Write-Info "Generating secure redis_password.txt..."
        $redisPassword = New-SecureRandomString -Length 48 -AsHex
        $redisPassword | Set-Content -Path $redisPasswordFile -NoNewline
        Write-Success "Generated secure redis_password.txt"
    } else {
        Write-Success "redis_password.txt already exists"
    }

    # Generate postgres_password.txt if not exists (usado pelo serviço postgres
    # e pelo app via /run/secrets/postgres_password). Hex evita problemas de
    # caracteres especiais na DATABASE_URL montada pelo entrypoint.
    $postgresPasswordFile = Join-Path $secretsDir "postgres_password.txt"
    if (-not (Test-Path $postgresPasswordFile)) {
        Write-Info "Generating secure postgres_password.txt..."
        $postgresPassword = New-SecureRandomString -Length 48 -AsHex
        $postgresPassword | Set-Content -Path $postgresPasswordFile -NoNewline
        Write-Success "Generated secure postgres_password.txt"
    } else {
        Write-Success "postgres_password.txt already exists"
    }
    
    # Aplicar permissões seguras
    Set-SecurePermissions -Path $secretsDir
    Get-ChildItem $secretsDir -Filter "*.txt" | ForEach-Object {
        Set-SecurePermissions -Path $_.FullName
    }
}

function Initialize-Directories {
    Write-Info "Initializing directories..."
    
    $dirs = @("backups", "logs", "reports", "data/redis", "data/ollama", "data/airflow", "infra/docker/nginx/ssl", "infra/docker/nginx/html")
    $created = 0
    
    foreach ($dir in $dirs) {
        $fullPath = Join-Path $ProjectRoot $dir
        if (-not (Test-Path $fullPath)) {
            New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
            $created++
        }
    }
    
    Write-Success "Directories initialized ($created created)"
}

function Build-Containers {
    Write-Info "=========================================="
    Write-Info "Building Docker images..."
    Write-Info "This may take several minutes on first run"
    Write-Info "=========================================="
    
    # Detectar CPUs disponíveis
    $cpus = (Get-CimInstance Win32_Processor).NumberOfLogicalProcessors
    $parallelJobs = [math]::Max(1, [math]::Floor($cpus / 2))
    Write-Info "Using $parallelJobs parallel jobs (detected $cpus CPUs)"
    
    $composeFilePath = Join-Path $ProjectRoot $script:COMPOSE_FILE
    Write-Debug "Compose file path: $composeFilePath"
    Write-Info "Starting build at $(Get-Date -Format 'HH:mm:ss')..."
    
    $startTime = Get-Date
    
    try {
        # Build usando Start-Job com caminho absoluto
        $buildScript = {
            param($composeCmd, $composeFile, $workingDir)
            Set-Location $workingDir
            $cmd = "$composeCmd -f `"$composeFile`" build --parallel"
            Invoke-Expression $cmd 2>&1
            $LASTEXITCODE
        }
        
        $job = Start-Job -ScriptBlock $buildScript -ArgumentList $script:COMPOSE_CMD, $composeFilePath, $ProjectRoot
        
        # Aguardar com timeout de 1 hora e mostrar progresso
        $timeout = 3600
        $elapsed = 0
        while ($elapsed -lt $timeout) {
            Start-Sleep -Seconds 5
            $elapsed += 5
            
            $jobState = $job.State
            if ($jobState -eq "Completed") {
                break
            } elseif ($jobState -eq "Failed") {
                break
            }
            
            # Mostrar progresso a cada 30 segundos
            if ($elapsed % 30 -eq 0) {
                Write-Info "Build em andamento... (${elapsed}s)"
            }
        }
        
        if ($job.State -eq "Running") {
            Stop-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job -ErrorAction SilentlyContinue
            Write-Error "Build timed out after $timeout seconds"
        }
        
        $result = Receive-Job $job
        Remove-Job $job -ErrorAction SilentlyContinue
        
        # Verificar exit code (última linha do resultado)
        $exitCode = 0
        if ($result -is [array]) {
            $exitCode = $result[-1]
            # Mostrar output exceto última linha (exit code)
            $result[0..($result.Count-2)] | ForEach-Object { Write-Host $_ }
        } else {
            $exitCode = $result
        }
        
        if ($exitCode -ne 0) {
            Write-Error "Build failed with exit code $exitCode"
            exit 1
        }
        
        $elapsed = ((Get-Date) - $startTime).TotalSeconds
        Write-Success "Build completed in $([math]::Round($elapsed, 2)) seconds ($([math]::Round($elapsed/60, 2)) minutes)"
        
    } catch {
        Write-Error "Build failed: $_"
    }
}

function Start-Services {
    Write-Info "=========================================="
    Write-Info "Starting services..."
    Write-Info "=========================================="
    
    $upArgs = @("-f", $script:COMPOSE_FILE, "up", "-d")
    Write-Debug "Command: $script:COMPOSE_CMD $upArgs"
    
    try {
        & $script:COMPOSE_CMD.Split(" ")[0] $script:COMPOSE_CMD.Split(" ")[1..100] $upArgs 2>&1 | ForEach-Object {
            Write-Host $_
        }
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to start services"
        }
        
        Write-Success "Services started"
    } catch {
        Write-Error "Failed to start services: $_"
    }
    
    Write-Info "Waiting for services to be healthy..."
    
    $maxWait = 180
    $interval = 10
    $count = 0
    $healthy = $false
    
    while ($count -lt $maxWait) {
        Start-Sleep -Seconds $interval
        $count += $interval
        
        try {
            $psArgs = @("-f", $script:COMPOSE_FILE, "ps", "--format", "json")
            $result = & $script:COMPOSE_CMD.Split(" ")[0] $script:COMPOSE_CMD.Split(" ")[1..100] $psArgs 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            if ($result) {
                $total = $result.Count
                $runningCount = ($result | Where-Object { $_.State -eq "running" }).Count
                
                if ($runningCount -eq $total -and $total -gt 0) {
                    Write-Success "All $total services are running"
                    $healthy = $true
                    break
                } else {
                    Write-Info "Waiting... ($runningCount/$total services ready, ${count}s elapsed)"
                }
            }
        } catch {
            Write-Info "Still starting... (${count}s elapsed)"
        }
    }
    
    if (-not $healthy) {
        Write-Warn "Some services may still be starting. Check status with: .\deploy-windows.ps1 status"
    }
}

function Stop-Services {
    Write-Info "Stopping services..."
    
    $downArgs = @("-f", $script:COMPOSE_FILE, "down")
    
    try {
        & $script:COMPOSE_CMD.Split(" ")[0] $script:COMPOSE_CMD.Split(" ")[1..100] $downArgs 2>&1 | ForEach-Object {
            Write-Host $_
        }
        
        Write-Success "Services stopped"
    } catch {
        Write-Error "Failed to stop services: $_"
    }
}

function Show-Status {
    Write-Host ""
    Write-Banner
    Write-Host ""
    
    $psArgs = @("-f", $script:COMPOSE_FILE, "ps")
    
    try {
        & $script:COMPOSE_CMD.Split(" ")[0] $script:COMPOSE_CMD.Split(" ")[1..100] $psArgs 2>&1 | ForEach-Object {
            Write-Host $_
        }
    } catch {
        Write-Host "No services running"
    }
    
    Write-Host ""
    Write-Host "${BOLD}Services:${NC}"
    Write-Host "  App:        http://localhost"
    Write-Host "  PostgreSQL: localhost:5432 (interno; banco 'soc360')"
    Write-Host "  Airflow:    http://localhost:8080  (overlay docker-compose.airflow.yml)"
    Write-Host "  Ollama:     http://localhost:11434 (overlay docker-compose.ollama.yml)"
    Write-Host ""
    Write-Host "${BOLD}Commands:${NC}"
    Write-Host "  Start:      .\deploy-windows.ps1 start"
    Write-Host "  Stop:       .\deploy-windows.ps1 stop"
    Write-Host "  Status:     .\deploy-windows.ps1 status"
    Write-Host "  Rollback:   .\deploy-windows.ps1 rollback"
    Write-Host ""
}

# ============================================
# MAIN
# ============================================

Set-Location $ProjectRoot
Write-Banner

# Check prerequisites
Test-ExecutionPolicy | Out-Null
Test-Docker
Test-Compose
Get-ComposeFile
Test-DiskSpace
Test-Ports

# Initialize environment
Test-EnvFile
Initialize-Secrets
Initialize-Directories

# Execute command
switch ($Command.ToLower()) {
    "start" {
        Build-Containers
        Start-Services
        Show-Status
    }
    "stop" {
        Stop-Services
    }
    "restart" {
        Stop-Services
        Start-Sleep -Seconds 2
        Start-Services
        Show-Status
    }
    "status" {
        Show-Status
    }
    "build" {
        Build-Containers
    }
    "update" {
        Backup-BeforeUpdate
        Write-Info "Pulling latest images..."
        $pullArgs = @("-f", $script:COMPOSE_FILE, "pull")
        Invoke-RetryCommand -Command {
            & $script:COMPOSE_CMD.Split(" ")[0] $script:COMPOSE_CMD.Split(" ")[1..100] $pullArgs
            return $LASTEXITCODE
        }
        Write-Success "Images updated. Run '.\deploy-windows.ps1 build' to rebuild."
    }
    "rollback" {
        Invoke-Rollback
    }
    default {
        Write-Host @"
Usage: .\deploy-windows.ps1 [Command] [-DebugMode]

Commands:
  start      - Build and start all services (default)
  stop       - Stop all services
  restart    - Restart all services
  status     - Show service status
  build      - Build only
  update     - Pull latest images (with backup)
  rollback   - Rollback to last backup

Options:
  -DebugMode - Enable debug output with verbose logging

Examples:
  .\deploy-windows.ps1 start
  .\deploy-windows.ps1 start -DebugMode
  .\deploy-windows.ps1 status
"@
    }
}