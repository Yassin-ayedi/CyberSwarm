# CyberSwarm data-collection driver — runs the 4 learning-method rungs x repeats,
# sequentially, each to its own runs/<name> dir. Launch once as a background job; it
# runs unattended (~8h). Pass -Model qwen2.5:7b to use the 7B fallback for every run.
#
#   powershell -File collect.ps1                 # 14B (default in the configs)
#   powershell -File collect.ps1 -Model qwen2.5:7b
param([string]$Model = "", [int]$Repeats = 2,
      [string[]]$Configs = @("no_learning", "reflect", "reflect_mem", "baseline"))

$env:Path = "$env:ProgramFiles\Docker\Docker\resources\bin;" + $env:Path
Set-Location $PSScriptRoot    # orchestrator/

$configs = $Configs
$modelArg = if ($Model) { @("--model", $Model) } else { @() }

Write-Output "collect.ps1 start $(Get-Date -Format o)  model=$(if($Model){$Model}else{'config-default'})  repeats=$Repeats"
foreach ($cfg in $configs) {
    for ($r = 1; $r -le $Repeats; $r++) {
        $name = "${cfg}_r${r}"
        Write-Output "`n==================== START $name  $(Get-Date -Format o) ===================="
        python main.py --config "../config/$cfg.yaml" --name $name --no-lab @modelArg 2>&1 | Out-Host
        Write-Output "==================== DONE  $name  exit=$LASTEXITCODE  $(Get-Date -Format o) ===================="
    }
}
Write-Output "`nALL RUNS COMPLETE $(Get-Date -Format o)"
