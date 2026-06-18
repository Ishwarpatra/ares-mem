# setup_ollama.ps1 — Local Ollama setup and model pulling script
$ErrorActionPreference = "Stop"

$workspace = "c:\Users\DELL\Desktop\codego\ares-mem"
$ollamaDir = Join-Path $workspace ".ollama"
$modelsDir = Join-Path $ollamaDir "models"
$zipPath = Join-Path $ollamaDir "ollama-windows-amd64.zip"
$exePath = Join-Path $ollamaDir "ollama.exe"

$modelName = "qwen2.5:0.5b-instruct"

# Create directories
if (-not (Test-Path $ollamaDir)) {
    New-Item -ItemType Directory -Force -Path $ollamaDir | Out-Null
}
if (-not (Test-Path $modelsDir)) {
    New-Item -ItemType Directory -Force -Path $modelsDir | Out-Null
}

# 1. Download Ollama if not present
if (-not (Test-Path $exePath)) {
    Write-Host "[Ollama] Downloading standalone ZIP..."
    $url = "https://github.com/ollama/ollama/releases/latest/download/ollama-windows-amd64.zip"
    Invoke-WebRequest -Uri $url -OutFile $zipPath
    
    Write-Host "[Ollama] Extracting ZIP..."
    Expand-Archive -Path $zipPath -DestinationPath $ollamaDir -Force
    Remove-Item $zipPath -Force
} else {
    Write-Host "[Ollama] Executable already exists."
}

# 2. Configure Environment
$env:OLLAMA_MODELS = $modelsDir
$env:OLLAMA_HOST = "127.0.0.1:11434"

# 3. Start Server if not running
$serverRunning = $false
try {
    [void](Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -ErrorAction Stop)
    $serverRunning = $true
    Write-Host "[Ollama] Server is already running."
} catch {
    Write-Host "[Ollama] Starting local server..."
    Start-Process -NoNewWindow -FilePath $exePath -ArgumentList "serve"
}

# 4. Wait for Server to be ready
$retries = 30
while (-not $serverRunning -and $retries -gt 0) {
    Start-Sleep -Seconds 1
    try {
        [void](Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -ErrorAction Stop)
        $serverRunning = $true
        Write-Host "[Ollama] Server is ready."
    } catch {
        $retries--
    }
}

if (-not $serverRunning) {
    Write-Error "[Ollama] Failed to start Ollama server."
    exit 1
}

# 5. Pull Model
Write-Host "[Ollama] Pulling model $modelName..."
Start-Process -FilePath $exePath -ArgumentList "pull $modelName" -Wait -NoNewWindow

Write-Host "[Ollama] Setup complete!"
