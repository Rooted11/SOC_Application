$serviceName = 'SocAgent'
$binaryPath = Join-Path $PSScriptRoot 'SocAgent.exe'

switch ($args[0]) {
    'install' {
        Write-Host "Installing $serviceName pointing to $binaryPath"
        New-Service -Name $serviceName -BinaryPathName $binaryPath -DisplayName 'SOC Log Collector' -StartupType Automatic -ErrorAction Stop
        Start-Service $serviceName
        break
    }
    'uninstall' {
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
            Stop-Service $serviceName -Force
            Remove-Service -Name $serviceName
        }
        break
    }
    default {
        Write-Host "Usage: .\install-service.ps1 install|uninstall"
    }
}
