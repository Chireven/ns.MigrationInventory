<#
.SYNOPSIS
  NetScaler migration-focused inventory (PowerShell 5.1).

.DESCRIPTION
  Produces reports that explain “what it does” instead of dumping every object:
    - CS routing flows: CS vServer -> CS policies -> CS actions -> target LB vServer
    - Responder behavior: bound policy -> rule -> action -> action definition (type + parameters)
    - Rewrite behavior: bound policy -> rule -> action -> action definition (type + parameters)
    - Backend mapping: LB vServer -> serviceGroup/service -> members -> monitors
    - Global bindings clearly called out

  Also flags “stray artifacts” for review:
    - Defined but never referenced/bound (likely unused)
    - Referenced but not defined (missing in provided config set)
    - Actions/policies defined but not bound anywhere

  DOT flow files are generated (Graphviz-safe UTF-8 without BOM). Rendering is optional.

.NOTES
  - Regex parser of common NetScaler CLI config lines.
  - Works best on full exported configs (ns.conf + included confs).

.PARAMETER ConfigFile
  Single config file path.

.PARAMETER VPXName
  Name used for report title and output folder naming.

.PARAMETER OutDir
  Output directory.

.PARAMETER GraphFormat
  dot|svg|png (DOT always written; svg/png only if Graphviz dot.exe works)

.PARAMETER DotExePath
  Optional explicit path to dot.exe

.PARAMETER SkipGraphRender
  Skip SVG/PNG rendering even if dot.exe exists.

.EXAMPLE
  .\get-nsMigrationOverview.ps1 -ConfigFile "C:\repo\ns\ns.conf" -VPXName "VPX-Prod-01" -OutDir "C:\temp\ns\report" -GraphFormat svg
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$ConfigFile,

  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$VPXName,

  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$OutDir = $(Join-Path -Path $psScriptRoot -ChildPath "Reports"),

  [ValidateSet('dot','svg','png')]
  [string]$GraphFormat = 'dot',

  [string]$DotExePath,

  [switch]$SkipGraphRender
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

trap {
  Write-Host "ERROR at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
  Write-Host "Line: $($_.InvocationInfo.Line)"
  break
}

# ---------------------------
# Helpers
# ---------------------------
function Ensure-Dir {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Out-FileUtf8NoBom {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$Content
  )
  $parent = Split-Path -Parent $Path
  if ($parent -and (-not (Test-Path -LiteralPath $parent))) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
  }
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function Get-SafeFileName {
  param([Parameter(Mandatory=$true)][string]$Name)
  $invalid = [System.IO.Path]::GetInvalidFileNameChars()
  $safe = $Name
  foreach ($c in $invalid) { $safe = $safe.Replace($c, "_") }
  return ($safe -replace '\s+', '_')
}

function Find-DotExe {
  param([string]$override)
  if ($override -and (Test-Path -LiteralPath $override)) { return $override }

  $cmd = Get-Command dot -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }

  $candidates = @(
    "$env:ProgramFiles\Graphviz\bin\dot.exe",
    "$env:ProgramFiles(x86)\Graphviz\bin\dot.exe"
  ) | Where-Object { Test-Path -LiteralPath $_ }

  if (@($candidates).Count -gt 0) { return @($candidates)[0] }
  return $null
}

function Render-GraphSafe {
  param(
    [Parameter(Mandatory=$true)][string]$DotExe,
    [Parameter(Mandatory=$true)][string]$DotPath,
    [Parameter(Mandatory=$true)][string]$Format
  )
  try {
    $outPath = [System.IO.Path]::ChangeExtension($DotPath, $Format)
    & $DotExe ("-T{0}" -f $Format) $DotPath ("-o{0}" -f $outPath) 2>$null | Out-Null
    if (Test-Path -LiteralPath $outPath) { return $outPath }
    return $null
  } catch {
    return $null
  }
}

function Read-NsConfigLines {
  param([Parameter(Mandatory=$true)][string]$Path)

  $raw = Get-Content -LiteralPath $Path -ErrorAction Stop

  $joined = New-Object System.Collections.Generic.List[string]
  $buffer = ""

  foreach ($line in $raw) {
    $l = ($line + "").Trim()
    if ($l.Length -eq 0) { continue }
    if ($l.StartsWith("#")) { continue }

    # best-effort inline comment strip " # ..."
    $hash = $l.IndexOf(" #")
    if ($hash -gt 0) { $l = $l.Substring(0, $hash).Trim() }

    # join trailing "\" continuations
    if ($l.EndsWith("\")) {
      $buffer += ($l.TrimEnd("\").Trim() + " ")
      continue
    }

    $buffer += $l
    $joined.Add($buffer.Trim())
    $buffer = ""
  }

  if ($buffer.Trim().Length -gt 0) { $joined.Add($buffer.Trim()) }
  return $joined
}

function New-NsModel {
  # Definitions
  [ordered]@{
    File = $null

    # Core objects
    CsVserver    = @{}  # name -> @{ proto; vip; port; raw }
    LbVserver    = @{}  # name -> @{ proto; vip; port; raw }
    Server       = @{}  # name -> addr
    ServiceGroup = @{}  # name -> proto
    Service      = @{}  # name -> @{ server; proto; port }
    Monitor      = @{}  # name -> type
    SslCertKey   = @{}  # name -> @{ cert; key }

    # CS logic
    CsAction     = @{}  # name -> @{ targetLbVserver }
    CsPolicy     = @{}  # name -> @{ rule; action }
    CsPolicyLabel= @{}  # name -> @{ }

    # Responder logic
    ResponderAction = @{} # name -> @{ type; params }
    ResponderPolicy = @{} # name -> @{ rule; action }

    # Rewrite logic
    RewriteAction = @{}   # name -> @{ type; params }
    RewritePolicy = @{}   # name -> @{ rule; action }

    # Policy data
    Patset  = @{}         # name -> $true
    Dataset = @{}         # name -> $true

    # Bindings (normalized)
    Bindings = @()        # objects: @{ TargetType; TargetName; Feature; PolicyName; Priority; BindType; Extra }
    # Examples:
    #  - CS vServer binds CS policy
    #  - LB/CS vServer binds responder policy (type=RESPONSE)
    #  - Global binds responder/rewrite
    #  - CS vServer binds policyLabel; policyLabel binds CS policy
    #  - LB vServer binds backend target (svc/sg)
    #  - serviceGroup members, monitors, etc.

    # Reference tracking for “stray artifact” detection
    Refs = @{
      UsedCsPolicy=@{}
      UsedCsAction=@{}
      UsedCsPolicyLabel=@{}
      UsedResponderPolicy=@{}
      UsedResponderAction=@{}
      UsedRewritePolicy=@{}
      UsedRewriteAction=@{}
      UsedLbVserver=@{}
      UsedServiceGroup=@{}
      UsedService=@{}
      UsedServer=@{}
      UsedMonitor=@{}
      UsedCertKey=@{}
    }
  }
}

function Mark-Ref {
  param(
    [Parameter(Mandatory=$true)]$model,
    [Parameter(Mandatory=$true)][string]$bucket,
    [Parameter(Mandatory=$true)][string]$name
  )
  if (-not $name) { return }
  $model.Refs[$bucket][$name] = $true
}

function Parse-RuleBetween {
  # Extracts text between -rule and -action (or end)
  param(
    [Parameter(Mandatory=$true)][string]$line,
    [Parameter(Mandatory=$true)][string]$startToken,
    [Parameter(Mandatory=$true)][string]$endToken
  )
  $si = $line.IndexOf($startToken)
  if ($si -lt 0) { return "" }
  $si += $startToken.Length
  $ei = $line.IndexOf($endToken, $si)
  if ($ei -lt 0) {
    return ($line.Substring($si).Trim())
  }
  return ($line.Substring($si, $ei - $si).Trim())
}

function Get-ServerAddress {
  param(
    [Parameter(Mandatory=$true)]$m,
    [Parameter(Mandatory=$true)][string]$serverName
  )
  if ($m.Server.ContainsKey($serverName)) { return $m.Server[$serverName] }
  return "[NOT FOUND]"
}

function Get-BackendLookup {
  param([Parameter(Mandatory=$true)]$m)

  $lbTargets = @{}
  $sgMembers = @{}
  $sgMonitors = @{}

  foreach ($b in @($m.Bindings | Where-Object { $_.BindType -eq "lb-vserver->backend-target" })) {
    if (-not $lbTargets.ContainsKey($b.TargetName)) { $lbTargets[$b.TargetName] = @() }
    $lbTargets[$b.TargetName] += $b.PolicyName
  }

  foreach ($b in @($m.Bindings | Where-Object { $_.BindType -eq "servicegroup->member-server" })) {
    if (-not $sgMembers.ContainsKey($b.TargetName)) { $sgMembers[$b.TargetName] = @() }
    $port = ($b.Extra -replace '^port=', '')
    $addr = Get-ServerAddress -m $m -serverName $b.PolicyName
    $sgMembers[$b.TargetName] += ("{0} ({1}:{2})" -f $b.PolicyName, $addr, $port)
  }

  foreach ($b in @($m.Bindings | Where-Object { $_.BindType -eq "servicegroup->monitor" })) {
    if (-not $sgMonitors.ContainsKey($b.TargetName)) { $sgMonitors[$b.TargetName] = @() }
    $sgMonitors[$b.TargetName] += $b.PolicyName
  }

  return [pscustomobject]@{
    LbTargets = $lbTargets
    ServiceGroupMembers = $sgMembers
    ServiceGroupMonitors = $sgMonitors
  }
}

function Parse-NsConfigFile {
  param([Parameter(Mandatory=$true)][string]$FilePath)

  $m = New-NsModel
  $m.File = (Resolve-Path -LiteralPath $FilePath).Path

  $lines = Read-NsConfigLines -Path $FilePath

  foreach ($l in $lines) {

    # -------------------
    # Definitions
    # -------------------
    if ($l -match '^\s*add\s+cs\s+vserver\s+(?<name>\S+)\s+(?<proto>\S+)\s+(?<vip>\S+)\s+(?<port>\d+)\b') {
      $m.CsVserver[$Matches.name] = @{ proto=$Matches.proto; vip=$Matches.vip; port=[int]$Matches.port; raw=$l }
      continue
    }

    if ($l -match '^\s*add\s+lb\s+vserver\s+(?<name>\S+)\s+(?<proto>\S+)\s+(?<vip>\S+)\s+(?<port>\d+)\b') {
      $m.LbVserver[$Matches.name] = @{ proto=$Matches.proto; vip=$Matches.vip; port=[int]$Matches.port; raw=$l }
      continue
    }

    if ($l -match '^\s*add\s+server\s+(?<name>\S+)\s+(?<addr>\S+)\b') {
      $m.Server[$Matches.name] = $Matches.addr
      continue
    }

    if ($l -match '^\s*add\s+serviceGroup\s+(?<name>\S+)\s+(?<proto>\S+)\b') {
      $m.ServiceGroup[$Matches.name] = @{ proto=$Matches.proto; raw=$l }
      continue
    }

    if ($l -match '^\s*add\s+service\s+(?<name>\S+)\s+(?<server>\S+)\s+(?<proto>\S+)\s+(?<port>\d+)\b') {
      $m.Service[$Matches.name] = @{ server=$Matches.server; proto=$Matches.proto; port=[int]$Matches.port; raw=$l }
      continue
    }

    if ($l -match '^\s*add\s+lb\s+monitor\s+(?<name>\S+)\s+(?<type>\S+)\b') {
      $m.Monitor[$Matches.name] = @{ type=$Matches.type; raw=$l }
      continue
    }

    if ($l -match '^\s*add\s+ssl\s+certKey\s+(?<name>\S+)\s+-cert\s+(?<cert>\S+)\s+-key\s+(?<key>\S+)\b') {
      $m.SslCertKey[$Matches.name] = @{ cert=$Matches.cert; key=$Matches.key; raw=$l }
      continue
    }

    # CS
    if ($l -match '^\s*add\s+cs\s+action\s+(?<name>\S+)\s+-targetLBVserver\s+(?<lb>\S+)\b') {
      $m.CsAction[$Matches.name] = @{ targetLbVserver=$Matches.lb; raw=$l }
      continue
    }

    if ($l -match '^\s*add\s+cs\s+policy\s+(?<name>\S+)\s+-rule\s+.+\s+-action\s+(?<action>\S+)\b') {
      $rule = Parse-RuleBetween -line $l -startToken "-rule" -endToken "-action"
      $m.CsPolicy[$Matches.name] = @{ rule=$rule; action=$Matches.action; raw=$l }
      continue
    }

    if ($l -match '^\s*add\s+cs\s+policylabel\s+(?<name>\S+)\b') {
      $m.CsPolicyLabel[$Matches.name] = @{ raw=$l }
      continue
    }

    # Responder
    if ($l -match '^\s*add\s+responder\s+action\s+(?<name>\S+)\s+(?<type>\S+)\b(?<rest>.*)$') {
      $m.ResponderAction[$Matches.name] = @{ type=$Matches.type; params=($Matches.rest.Trim()); raw=$l }
      continue
    }

    if ($l -match '^\s*add\s+responder\s+policy\s+(?<name>\S+)\s+-rule\s+.+\s+-action\s+(?<action>\S+)\b') {
      $rule = Parse-RuleBetween -line $l -startToken "-rule" -endToken "-action"
      $m.ResponderPolicy[$Matches.name] = @{ rule=$rule; action=$Matches.action; raw=$l }
      continue
    }

    # Rewrite
    if ($l -match '^\s*add\s+rewrite\s+action\s+(?<name>\S+)\s+(?<type>\S+)\b(?<rest>.*)$') {
      $m.RewriteAction[$Matches.name] = @{ type=$Matches.type; params=($Matches.rest.Trim()); raw=$l }
      continue
    }

    # common: add rewrite policy <name> <rule> <action>
    if ($l -match '^\s*add\s+rewrite\s+policy\s+(?<name>\S+)\s+.+\s+(?<action>\S+)\s*$') {
      # try to separate rule from action by removing leading "add rewrite policy <name>" and trailing "<action>"
      $prefix = ("add rewrite policy {0}" -f $Matches.name)
      $body = $l.Trim()
      if ($body.StartsWith($prefix)) { $body = $body.Substring($prefix.Length).Trim() }
      if ($body.EndsWith(" " + $Matches.action)) { $rule = $body.Substring(0, $body.Length - (" " + $Matches.action).Length).Trim() }
      else { $rule = $body }
      $m.RewritePolicy[$Matches.name] = @{ rule=$rule; action=$Matches.action; raw=$l }
      continue
    }

    # Data
    if ($l -match '^\s*add\s+policy\s+patset\s+(?<name>\S+)\b') { $m.Patset[$Matches.name]=$true; continue }
    if ($l -match '^\s*add\s+policy\s+dataset\s+(?<name>\S+)\b') { $m.Dataset[$Matches.name]=$true; continue }

    # -------------------
    # Bindings (normalized)
    # -------------------

    # CS vServer binds CS policy
    if ($l -match '^\s*bind\s+cs\s+vserver\s+(?<vs>\S+)\s+-policyName\s+(?<pol>\S+)(?<rest>.*)$') {
      $vsName = $Matches['vs']
      $polName = $Matches['pol']
      if (-not $vsName -or -not $polName) { continue }
      $priority = $null
      if ($Matches['rest'] -match '-priority\s+(?<p>\d+)') { $priority = [int]$Matches.p }
      $m.Bindings += @{
        TargetType="CS vServer"; TargetName=$vsName
        Feature="CS"; PolicyName=$polName; Priority=$priority
        BindType="cs-vserver->cs-policy"; Extra=$l
      }
      Mark-Ref $m "UsedCsPolicy" $polName
      continue
    }

    # CS vServer binds policyLabel
    if ($l -match '^\s*bind\s+cs\s+vserver\s+(?<vs>\S+)\s+-policyLabel\s+(?<pl>\S+)(?<rest>.*)$') {
      $vsName = $Matches['vs']
      $labelName = $Matches['pl']
      if (-not $vsName -or -not $labelName) { continue }
      $priority = $null
      if ($Matches['rest'] -match '-priority\s+(?<p>\d+)') { $priority = [int]$Matches.p }
      $m.Bindings += @{
        TargetType="CS vServer"; TargetName=$vsName
        Feature="CS"; PolicyName=$labelName; Priority=$priority
        BindType="cs-vserver->cs-policylabel"; Extra=$l
      }
      Mark-Ref $m "UsedCsPolicyLabel" $labelName
      continue
    }

    # CS policyLabel binds CS policy
    if ($l -match '^\s*bind\s+cs\s+policylabel\s+(?<pl>\S+)\s+-policyName\s+(?<pol>\S+)(?<rest>.*)$') {
      $labelName = $Matches['pl']
      $polName = $Matches['pol']
      if (-not $labelName -or -not $polName) { continue }
      $priority = $null
      if ($Matches['rest'] -match '-priority\s+(?<p>\d+)') { $priority = [int]$Matches.p }
      $m.Bindings += @{
        TargetType="CS Policy Label"; TargetName=$labelName
        Feature="CS"; PolicyName=$polName; Priority=$priority
        BindType="cs-policylabel->cs-policy"; Extra=$l
      }
      Mark-Ref $m "UsedCsPolicyLabel" $labelName
      Mark-Ref $m "UsedCsPolicy" $polName
      continue
    }

    # LB vServer binds backend (serviceGroup or service)
    if ($l -match '^\s*bind\s+lb\s+vserver\s+(?<lb>\S+)\s+(?<target>\S+)\b') {
      $m.Bindings += @{
        TargetType="LB vServer"; TargetName=$Matches.lb
        Feature="LB"; PolicyName=$Matches.target; Priority=$null
        BindType="lb-vserver->backend-target"; Extra=$l
      }
      Mark-Ref $m "UsedLbVserver" $Matches.lb
      # heuristic: mark as sg or svc later when building views
      continue
    }

    # serviceGroup member (server + port)
    if ($l -match '^\s*bind\s+serviceGroup\s+(?<sg>\S+)\s+(?<server>\S+)\s+(?<port>\d+)\b') {
      $m.Bindings += @{
        TargetType="Service Group"; TargetName=$Matches.sg
        Feature="LB"; PolicyName=$Matches.server; Priority=$null
        BindType="servicegroup->member-server"; Extra=("port={0}" -f $Matches.port)
      }
      Mark-Ref $m "UsedServiceGroup" $Matches.sg
      Mark-Ref $m "UsedServer" $Matches.server
      continue
    }

    # serviceGroup -> monitor
    if ($l -match '^\s*bind\s+serviceGroup\s+(?<sg>\S+)\s+-monitorName\s+(?<mon>\S+)\b') {
      $m.Bindings += @{
        TargetType="Service Group"; TargetName=$Matches.sg
        Feature="LB"; PolicyName=$Matches.mon; Priority=$null
        BindType="servicegroup->monitor"; Extra=$l
      }
      Mark-Ref $m "UsedServiceGroup" $Matches.sg
      Mark-Ref $m "UsedMonitor" $Matches.mon
      continue
    }

    # service -> monitor
    if ($l -match '^\s*bind\s+service\s+(?<svc>\S+)\s+-monitorName\s+(?<mon>\S+)\b') {
      $m.Bindings += @{
        TargetType="Service"; TargetName=$Matches.svc
        Feature="LB"; PolicyName=$Matches.mon; Priority=$null
        BindType="service->monitor"; Extra=$l
      }
      Mark-Ref $m "UsedService" $Matches.svc
      Mark-Ref $m "UsedMonitor" $Matches.mon
      continue
    }

    # global responder
    if ($l -match '^\s*bind\s+responder\s+global\s+(?<pol>\S+)(?<rest>.*)$') {
      $priority = $null
      if ($Matches.rest -match '-priority\s+(?<p>\d+)') { $priority = [int]$Matches.p }
      $m.Bindings += @{
        TargetType="Global"; TargetName="global"
        Feature="Responder"; PolicyName=$Matches.pol; Priority=$priority
        BindType="responder-global->policy"; Extra=$l
      }
      Mark-Ref $m "UsedResponderPolicy" $Matches.pol
      continue
    }

    # responder bound to vServer (type=RESPONSE)
    if ($l -match '^\s*bind\s+(?<kind>\S+)\s+vserver\s+(?<vs>\S+)\s+-policyName\s+(?<pol>\S+).*-type\s+RESPONSE\b(?<rest>.*)$') {
      $priority = $null
      if ($Matches.rest -match '-priority\s+(?<p>\d+)') { $priority = [int]$Matches.p }
      $kindLabel = switch ($Matches.kind.ToLower()) {
        "cs" { "CS vServer" }
        "lb" { "LB vServer" }
        default { "{0} vServer" -f $Matches.kind.ToUpper() }
      }
      $m.Bindings += @{
        TargetType=$kindLabel; TargetName=$Matches.vs
        Feature="Responder"; PolicyName=$Matches.pol; Priority=$priority
        BindType="responder->policy"; Extra=$l
      }
      Mark-Ref $m "UsedResponderPolicy" $polName
      continue
    }

    # global rewrite
    if ($l -match '^\s*bind\s+rewrite\s+global\s+(?<pol>\S+)(?<rest>.*)$') {
      $priority = $null
      if ($Matches.rest -match '-priority\s+(?<p>\d+)') { $priority = [int]$Matches.p }
      $m.Bindings += @{
        TargetType="Global"; TargetName="global"
        Feature="Rewrite"; PolicyName=$Matches.pol; Priority=$priority
        BindType="rewrite-global->policy"; Extra=$l
      }
      Mark-Ref $m "UsedRewritePolicy" $Matches.pol
      continue
    }

    # rewrite bound to CS/LB vServer (type=REQUEST/RESPONSE)
    if ($l -match '^\s*bind\s+(?<kind>cs|lb)\s+vserver\s+(?<vs>\S+)\s+-policyName\s+(?<pol>\S+).*-type\s+(?<rtype>REQUEST|RESPONSE)\b(?<rest>.*)$') {
      $vsName = $Matches['vs']
      $polName = $Matches['pol']
      if (-not $vsName -or -not $polName) { continue }
      $priority = $null
      if ($Matches['rest'] -match '-priority\s+(?<p>\d+)') { $priority = [int]$Matches.p }
      $t = if ($Matches.kind -eq "cs") { "CS vServer" } else { "LB vServer" }
      $m.Bindings += @{
        TargetType=$t; TargetName=$vsName
        Feature="Rewrite"; PolicyName=$polName; Priority=$priority
        BindType=("rewrite-{0}->policy" -f $Matches.rtype.ToLower()); Extra=$l
      }
      Mark-Ref $m "UsedRewritePolicy" $polName
      continue
    }

    # SSL vServer cert binding (best-effort)
    if ($l -match '^\s*bind\s+ssl\s+vserver\s+(?<vs>\S+)\s+-certkeyName\s+(?<ck>\S+)\b') {
      $vsName = $Matches['vs']
      $certName = $Matches['ck']
      if (-not $vsName -or -not $certName) { continue }
      $m.Bindings += @{
        TargetType="SSL vServer"; TargetName=$vsName
        Feature="SSL"; PolicyName=$certName; Priority=$null
        BindType="ssl-vserver->certkey"; Extra=$l
      }
      Mark-Ref $m "UsedCertKey" $certName
      continue
    }
  }

  # Derived refs: policy->action usage
  foreach ($p in $m.CsPolicy.Keys)       { if ($m.Refs.UsedCsPolicy.ContainsKey($p)) { Mark-Ref $m "UsedCsAction" $m.CsPolicy[$p].action } }
  foreach ($p in $m.ResponderPolicy.Keys){ if ($m.Refs.UsedResponderPolicy.ContainsKey($p)) { Mark-Ref $m "UsedResponderAction" $m.ResponderPolicy[$p].action } }
  foreach ($p in $m.RewritePolicy.Keys)  { if ($m.Refs.UsedRewritePolicy.ContainsKey($p)) { Mark-Ref $m "UsedRewriteAction" $m.RewritePolicy[$p].action } }

  return $m
}

# ---------------------------
# Build “meaningful views”
# ---------------------------
function Get-CsFlows {
  param([Parameter(Mandatory=$true)]$m)

  $rows = @()
  $backendLookup = Get-BackendLookup -m $m

  # direct CS policy binds
  $direct = @($m.Bindings | Where-Object { $_.BindType -eq "cs-vserver->cs-policy" })
  # label binds and label->policy binds
  $vsToLabel = @($m.Bindings | Where-Object { $_.BindType -eq "cs-vserver->cs-policylabel" })
  $labelToPol= @($m.Bindings | Where-Object { $_.BindType -eq "cs-policylabel->cs-policy" })

  function Get-LbDetails($lbName) {
    if (-not $lbName) {
      return [pscustomobject]@{ Vip=""; Port=$null; Proto=""; Backends=@(); BackendDetails=@(); Members=@(); Monitors=@() }
    }

    $lbDef = if ($m.LbVserver.ContainsKey($lbName)) { $m.LbVserver[$lbName] } else { $null }
    $targets = if ($backendLookup.LbTargets.ContainsKey($lbName)) { @($backendLookup.LbTargets[$lbName]) } else { @() }

    $details = @()
    $members = @()
    $monitors = @()

    foreach ($t in $targets) {
      if ($m.ServiceGroup.ContainsKey($t)) {
        $details += ("ServiceGroup {0} (proto={1})" -f $t, $m.ServiceGroup[$t].proto)
        if ($backendLookup.ServiceGroupMembers.ContainsKey($t)) {
          $members += @($backendLookup.ServiceGroupMembers[$t])
        }
        if ($backendLookup.ServiceGroupMonitors.ContainsKey($t)) {
          $monitors += @($backendLookup.ServiceGroupMonitors[$t])
        }
      } elseif ($m.Service.ContainsKey($t)) {
        $svc = $m.Service[$t]
        $addr = Get-ServerAddress -m $m -serverName $svc.server
        $details += ("Service {0} (server={1} addr={2} port={3} proto={4})" -f $t, $svc.server, $addr, $svc.port, $svc.proto)
      } else {
        $details += ("{0} [NOT FOUND]" -f $t)
      }
    }

    return [pscustomobject]@{
      Vip = if ($lbDef) { $lbDef.vip } else { "" }
      Port = if ($lbDef) { $lbDef.port } else { $null }
      Proto = if ($lbDef) { $lbDef.proto } else { "" }
      Backends = $targets
      BackendDetails = $details
      Members = $members
      Monitors = $monitors
    }
  }

  foreach ($b in $direct) {
    $pol = $b.PolicyName
    $polDef = $m.CsPolicy[$pol]
    $csActName = if ($polDef) { $polDef.action } else { "" }
    $csActDef  = if ($csActName) { $m.CsAction[$csActName] } else { $null }
    $targetLb  = if ($csActDef) { $csActDef.targetLbVserver } else { "" }
    if ($targetLb) { Mark-Ref $m "UsedLbVserver" $targetLb }
    $lbDetails = Get-LbDetails -lbName $targetLb
    $csDef = if ($m.CsVserver.ContainsKey($b.TargetName)) { $m.CsVserver[$b.TargetName] } else { $null }

    $rows += [pscustomobject]@{
      CsVserver = $b.TargetName
      CsVip    = if ($csDef) { $csDef.vip } else { "" }
      CsPort   = if ($csDef) { $csDef.port } else { $null }
      CsProto  = if ($csDef) { $csDef.proto } else { "" }
      Source   = "direct"
      PolicyLabel = ""
      VserverPriority = $b.Priority
      PolicyPriority = $null
      CsPolicy = $pol
      MatchRule= if ($polDef) { $polDef.rule } else { "[NOT FOUND]" }
      CsAction = if ($csActName) { $csActName } else { "[NOT FOUND]" }
      TargetLbVserver = if ($targetLb) { $targetLb } else { "" }
      LbVip = $lbDetails.Vip
      LbPort = $lbDetails.Port
      LbProto = $lbDetails.Proto
      LbBackends = if (@($lbDetails.Backends).Count -gt 0) { $lbDetails.Backends -join ", " } else { "" }
      LbBackendDetails = if (@($lbDetails.BackendDetails).Count -gt 0) { $lbDetails.BackendDetails -join "; " } else { "" }
      LbServiceGroupMembers = if (@($lbDetails.Members).Count -gt 0) { $lbDetails.Members -join ", " } else { "" }
      LbServiceGroupMonitors = if (@($lbDetails.Monitors).Count -gt 0) { $lbDetails.Monitors -join ", " } else { "" }
    }
  }

  foreach ($vb in $vsToLabel) {
    $label = $vb.PolicyName
    $lp = @($labelToPol | Where-Object { $_.TargetName -eq $label })
    foreach ($lb in $lp) {
      $pol = $lb.PolicyName
      $polDef = $m.CsPolicy[$pol]
      $csActName = if ($polDef) { $polDef.action } else { "" }
      $csActDef  = if ($csActName) { $m.CsAction[$csActName] } else { $null }
      $targetLb  = if ($csActDef) { $csActDef.targetLbVserver } else { "" }
      if ($targetLb) { Mark-Ref $m "UsedLbVserver" $targetLb }
      $lbDetails = Get-LbDetails -lbName $targetLb
      $csDef = if ($m.CsVserver.ContainsKey($vb.TargetName)) { $m.CsVserver[$vb.TargetName] } else { $null }

      $rows += [pscustomobject]@{
        CsVserver = $vb.TargetName
        CsVip    = if ($csDef) { $csDef.vip } else { "" }
        CsPort   = if ($csDef) { $csDef.port } else { $null }
        CsProto  = if ($csDef) { $csDef.proto } else { "" }
        Source   = "label"
        PolicyLabel = $label
        VserverPriority = $vb.Priority
        PolicyPriority = $lb.Priority
        CsPolicy = $pol
        MatchRule= if ($polDef) { $polDef.rule } else { "[NOT FOUND]" }
        CsAction = if ($csActName) { $csActName } else { "[NOT FOUND]" }
        TargetLbVserver = if ($targetLb) { $targetLb } else { "" }
        LbVip = $lbDetails.Vip
        LbPort = $lbDetails.Port
        LbProto = $lbDetails.Proto
        LbBackends = if (@($lbDetails.Backends).Count -gt 0) { $lbDetails.Backends -join ", " } else { "" }
        LbBackendDetails = if (@($lbDetails.BackendDetails).Count -gt 0) { $lbDetails.BackendDetails -join "; " } else { "" }
        LbServiceGroupMembers = if (@($lbDetails.Members).Count -gt 0) { $lbDetails.Members -join ", " } else { "" }
        LbServiceGroupMonitors = if (@($lbDetails.Monitors).Count -gt 0) { $lbDetails.Monitors -join ", " } else { "" }
      }
    }
  }

  return @($rows | Sort-Object CsVserver, @{Expression="VserverPriority"; Ascending=$true}, @{Expression="PolicyPriority"; Ascending=$true})
}

function Get-ResponderTable {
  param([Parameter(Mandatory=$true)]$m)

  $rows = @()
  $binds = @($m.Bindings | Where-Object { $_.Feature -eq "Responder" -and $_.PolicyName })

  foreach ($b in $binds) {
    $pol = $b.PolicyName
    $polDef = $m.ResponderPolicy[$pol]
    $actName = if ($polDef) { $polDef.action } else { "" }
    $actDef  = if ($actName) { $m.ResponderAction[$actName] } else { $null }

    if ($actName) { Mark-Ref $m "UsedResponderAction" $actName }

    $rows += [pscustomobject]@{
      BoundToType = $b.TargetType
      BoundToName = $b.TargetName
      Priority    = $b.Priority
      Policy      = $pol
      MatchRule   = if ($polDef) { $polDef.rule } else { "[NOT FOUND]" }
      Action      = if ($actName) { $actName } else { "[NOT FOUND]" }
      ActionType  = if ($actDef) { $actDef.type } else { "" }
      ActionParams= if ($actDef) { $actDef.params } else { "" }
    }
  }

  return @($rows | Sort-Object BoundToType, BoundToName, @{Expression="Priority"; Ascending=$true}, Policy)
}

function Get-RewriteTable {
  param([Parameter(Mandatory=$true)]$m)

  $rows = @()
  $binds = @($m.Bindings | Where-Object { $_.Feature -eq "Rewrite" -and $_.PolicyName })

  foreach ($b in $binds) {
    $pol = $b.PolicyName
    $polDef = $m.RewritePolicy[$pol]
    $actName = if ($polDef) { $polDef.action } else { "" }
    $actDef  = if ($actName) { $m.RewriteAction[$actName] } else { $null }

    if ($actName) { Mark-Ref $m "UsedRewriteAction" $actName }

    $rows += [pscustomobject]@{
      BoundToType = $b.TargetType
      BoundToName = $b.TargetName
      Priority    = $b.Priority
      Policy      = $pol
      MatchRule   = if ($polDef) { $polDef.rule } else { "[NOT FOUND]" }
      Action      = if ($actName) { $actName } else { "[NOT FOUND]" }
      ActionType  = if ($actDef) { $actDef.type } else { "" }
      ActionParams= if ($actDef) { $actDef.params } else { "" }
    }
  }

  return @($rows | Sort-Object BoundToType, BoundToName, @{Expression="Priority"; Ascending=$true}, Policy)
}

function Get-BackendTable {
  param([Parameter(Mandatory=$true)]$m)

  $rows = @()
  $backendLookup = Get-BackendLookup -m $m

  foreach ($lb in $backendLookup.LbTargets.Keys) {
    foreach ($backend in @($backendLookup.LbTargets[$lb])) {

      # is it a serviceGroup or a service?
      $isSg = $m.ServiceGroup.ContainsKey($backend)
      $isSvc= $m.Service.ContainsKey($backend)

      if ($isSg) { Mark-Ref $m "UsedServiceGroup" $backend }
      if ($isSvc){ Mark-Ref $m "UsedService" $backend }

      $details = if ($isSg) {
        ("proto={0}" -f $m.ServiceGroup[$backend].proto)
      } elseif ($isSvc) {
        $svc = $m.Service[$backend]
        $addr = Get-ServerAddress -m $m -serverName $svc.server
        ("server={0} addr={1} port={2} proto={3}" -f $svc.server, $addr, $svc.port, $svc.proto)
      } else {
        "[NOT FOUND]"
      }

      $rows += [pscustomobject]@{
        LbVserver = $lb
        BackendType = if ($isSg) { "Service Group" } elseif ($isSvc) { "Service" } else { "Unknown" }
        BackendName = $backend
        BackendDetails = $details
      }
    }
  }

  # expand serviceGroup members + monitors
  $expanded = @()
  foreach ($r in $rows) {
    if ($r.BackendType -ne "Service Group") { continue }
    $sg = $r.BackendName

    $memberText = if ($backendLookup.ServiceGroupMembers.ContainsKey($sg)) {
      @($backendLookup.ServiceGroupMembers[$sg]) -join ", "
    } else { "" }

    $monText = if ($backendLookup.ServiceGroupMonitors.ContainsKey($sg)) {
      @($backendLookup.ServiceGroupMonitors[$sg]) -join ", "
    } else { "" }

    $expanded += [pscustomobject]@{
      LbVserver = $r.LbVserver
      ServiceGroup = $sg
      Members = $memberText
      Monitors = $monText
    }
  }

  return [pscustomobject]@{
    LbToBackend = @($rows | Sort-Object LbVserver, BackendType, BackendName)
    ServiceGroupExpansion = @($expanded | Sort-Object LbVserver, ServiceGroup)
  }
}

function Get-EntryPoints {
  param([Parameter(Mandatory=$true)]$m)

  $entrypoints = @()

  foreach ($k in $m.CsVserver.Keys) {
    $o = $m.CsVserver[$k]
    $entrypoints += [pscustomobject]@{
      Type="CS vServer"
      Name=$k
      Address=("{0}:{1}" -f $o.vip, $o.port)
      Proto=$o.proto
      ReferencedByCS=""
    }
  }
  foreach ($k in $m.LbVserver.Keys) {
    $o = $m.LbVserver[$k]
    $entrypoints += [pscustomobject]@{
      Type="LB vServer"
      Name=$k
      Address=("{0}:{1}" -f $o.vip, $o.port)
      Proto=$o.proto
      ReferencedByCS = if ($m.Refs.UsedLbVserver.ContainsKey($k)) { "Yes" } else { "No" }
    }
  }

  return $entrypoints
}

# ---------------------------
# Stray artifact detection
# ---------------------------
function Get-StrayArtifacts {
  param([Parameter(Mandatory=$true)]$m)

  $items = New-Object 'System.Collections.Generic.List[object]'

  function Add-Stray($type, $name, $reason) {
    $null = $items.Add([pscustomobject]@{ Type=$type; Name=$name; Reason=$reason })
  }

  # Defined but not used
  foreach ($k in $m.CsPolicy.Keys)        { if (-not $m.Refs.UsedCsPolicy.ContainsKey($k)) { Add-Stray "CS Policy" $k "Defined but not bound (unused?)" } }
  foreach ($k in $m.CsAction.Keys)        { if (-not $m.Refs.UsedCsAction.ContainsKey($k)) { Add-Stray "CS Action" $k "Defined but not referenced by used CS policy" } }
  foreach ($k in $m.CsPolicyLabel.Keys)   { if (-not $m.Refs.UsedCsPolicyLabel.ContainsKey($k)) { Add-Stray "CS Policy Label" $k "Defined but not attached/bound (unused?)" } }

  foreach ($k in $m.ResponderPolicy.Keys) { if (-not $m.Refs.UsedResponderPolicy.ContainsKey($k)) { Add-Stray "Responder Policy" $k "Defined but not bound (unused?)" } }
  foreach ($k in $m.ResponderAction.Keys) { if (-not $m.Refs.UsedResponderAction.ContainsKey($k)) { Add-Stray "Responder Action" $k "Defined but not referenced by used policy" } }

  foreach ($k in $m.RewritePolicy.Keys)   { if (-not $m.Refs.UsedRewritePolicy.ContainsKey($k)) { Add-Stray "Rewrite Policy" $k "Defined but not bound (unused?)" } }
  foreach ($k in $m.RewriteAction.Keys)   { if (-not $m.Refs.UsedRewriteAction.ContainsKey($k)) { Add-Stray "Rewrite Action" $k "Defined but not referenced by used policy" } }

  foreach ($k in $m.ServiceGroup.Keys)    { if (-not $m.Refs.UsedServiceGroup.ContainsKey($k)) { Add-Stray "Service Group" $k "Defined but not referenced by LB vServer / member bind" } }
  foreach ($k in $m.Service.Keys)         { if (-not $m.Refs.UsedService.ContainsKey($k)) { Add-Stray "Service" $k "Defined but not referenced by LB vServer / monitor bind" } }
  foreach ($k in $m.Server.Keys)          { if (-not $m.Refs.UsedServer.ContainsKey($k)) { Add-Stray "Server" $k "Defined but not referenced in service/serviceGroup members" } }
  foreach ($k in $m.Monitor.Keys)         { if (-not $m.Refs.UsedMonitor.ContainsKey($k)) { Add-Stray "Monitor" $k "Defined but not bound to service/serviceGroup" } }
  foreach ($k in $m.SslCertKey.Keys)      { if (-not $m.Refs.UsedCertKey.ContainsKey($k)) { Add-Stray "SSL CertKey" $k "Defined but not bound to an SSL vServer (in provided files)" } }

  # Referenced but not defined (in provided set)
  foreach ($k in $m.Refs.UsedCsPolicy.Keys)        { if (-not $m.CsPolicy.ContainsKey($k)) { Add-Stray "CS Policy" $k "Referenced but not defined (missing file?)" } }
  foreach ($k in $m.Refs.UsedCsAction.Keys)        { if (-not $m.CsAction.ContainsKey($k)) { Add-Stray "CS Action" $k "Referenced but not defined (missing file?)" } }
  foreach ($k in $m.Refs.UsedCsPolicyLabel.Keys)   { if (-not $m.CsPolicyLabel.ContainsKey($k)) { Add-Stray "CS Policy Label" $k "Referenced but not defined (missing file?)" } }

  foreach ($k in $m.Refs.UsedResponderPolicy.Keys) { if (-not $m.ResponderPolicy.ContainsKey($k)) { Add-Stray "Responder Policy" $k "Referenced but not defined (missing file?)" } }
  foreach ($k in $m.Refs.UsedResponderAction.Keys) { if (-not $m.ResponderAction.ContainsKey($k)) { Add-Stray "Responder Action" $k "Referenced but not defined (missing file?)" } }

  foreach ($k in $m.Refs.UsedRewritePolicy.Keys)   { if (-not $m.RewritePolicy.ContainsKey($k)) { Add-Stray "Rewrite Policy" $k "Referenced but not defined (missing file?)" } }
  foreach ($k in $m.Refs.UsedRewriteAction.Keys)   { if (-not $m.RewriteAction.ContainsKey($k)) { Add-Stray "Rewrite Action" $k "Referenced but not defined (missing file?)" } }

  foreach ($k in $m.Refs.UsedLbVserver.Keys)       { if (-not $m.LbVserver.ContainsKey($k)) { Add-Stray "LB vServer" $k "Referenced but not defined (missing file?)" } }
  foreach ($k in $m.Refs.UsedServiceGroup.Keys)    { if (-not $m.ServiceGroup.ContainsKey($k)) { Add-Stray "Service Group" $k "Referenced but not defined (missing file?)" } }
  foreach ($k in $m.Refs.UsedService.Keys)         { if (-not $m.Service.ContainsKey($k)) { Add-Stray "Service" $k "Referenced but not defined (missing file?)" } }
  foreach ($k in $m.Refs.UsedServer.Keys)          { if (-not $m.Server.ContainsKey($k)) { Add-Stray "Server" $k "Referenced but not defined (missing file?)" } }
  foreach ($k in $m.Refs.UsedMonitor.Keys)         { if (-not $m.Monitor.ContainsKey($k)) { Add-Stray "Monitor" $k "Referenced but not defined (missing file?)" } }
  foreach ($k in $m.Refs.UsedCertKey.Keys)         { if (-not $m.SslCertKey.ContainsKey($k)) { Add-Stray "SSL CertKey" $k "Referenced but not defined (missing file?)" } }

  return @($items | Sort-Object Type, Name, Reason)
}

# ---------------------------
# Graph (meaningful, not exhaustive)
# ---------------------------
function Write-EntryPointFlowDot {
  param(
    [Parameter(Mandatory=$true)]$m,
    [Parameter(Mandatory=$true)]$entrypoint,
    [Parameter(Mandatory=$true)][string]$baseName,
    [Parameter(Mandatory=$true)][string]$dir,
    [Parameter(Mandatory=$true)]$csFlows
  )

  $dotPath = Join-Path $dir ($baseName + ".flow.dot")
  $backendLookup = Get-BackendLookup -m $m

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("digraph netscaler {")
  $lines.Add("  rankdir=LR;")
  $lines.Add('  node [shape=box, fontsize=10];')
  $lines.Add('  edge [fontsize=9];')
  $lines.Add(('  label="Entry Point Flow: {0}"; labelloc="t"; fontsize=18;' -f $entrypoint.Name))

  $seen = @{}
  function Node($id, $label) {
    if ($seen.ContainsKey($id)) { return }
    $seen[$id] = $true
    $safe = ($label -replace '"','\"')
    $lines.Add(("  {0} [label=""{1}""];" -f $id, $safe))
  }
  function Edge($from, $to, $label) {
    $safe = ($label -replace '"','\"')
    $lines.Add(("  {0} -> {1} [label=""{2}""];" -f $from, $to, $safe))
  }
  function Id($prefix, $name) {
    return (($prefix + "_" + ($name -replace '[^a-zA-Z0-9_]', '_')))
  }
  function Add-LbTargets([string]$lbName) {
    if (-not $lbName) { return }
    $lbId = Id "lb" $lbName
    Node $lbId ("LB vServer`n{0}" -f $lbName)
    $targets = if ($backendLookup.LbTargets.ContainsKey($lbName)) { @($backendLookup.LbTargets[$lbName]) } else { @() }
    foreach ($t in $targets) {
      if ($m.ServiceGroup.ContainsKey($t)) {
        $sgId = Id "sg" $t
        Node $sgId ("Service Group`n{0}" -f $t)
        Edge $lbId $sgId "backend"
        if ($backendLookup.ServiceGroupMembers.ContainsKey($t)) {
          foreach ($member in @($backendLookup.ServiceGroupMembers[$t])) {
            $memId = Id "member" ($t + "_" + $member)
            Node $memId ("Member`n{0}" -f $member)
            Edge $sgId $memId "member"
          }
        }
        if ($backendLookup.ServiceGroupMonitors.ContainsKey($t)) {
          foreach ($mon in @($backendLookup.ServiceGroupMonitors[$t])) {
            $monId = Id "mon" ($t + "_" + $mon)
            Node $monId ("Monitor`n{0}" -f $mon)
            Edge $sgId $monId "monitor"
          }
        }
      } elseif ($m.Service.ContainsKey($t)) {
        $svcId = Id "svc" $t
        Node $svcId ("Service`n{0}" -f $t)
        Edge $lbId $svcId "backend"
      } else {
        $unkId = Id "backend" $t
        Node $unkId ("Backend`n{0}" -f $t)
        Edge $lbId $unkId "backend"
      }
    }
  }

  if ($entrypoint.Type -eq "CS vServer") {
    foreach ($r in @($csFlows | Where-Object { $_.CsVserver -eq $entrypoint.Name })) {
      $vsId = Id "cs" $r.CsVserver
      $polId= Id "csp" $r.CsPolicy
      $actId= Id "csa" $r.CsAction
      $lbId = if ($r.TargetLbVserver) { Id "lb" $r.TargetLbVserver } else { $null }
      $prioLabel = if ($r.Source -eq "label") {
        "vs={0},pol={1}" -f $r.VserverPriority, $r.PolicyPriority
      } else {
        "prio={0}" -f $r.VserverPriority
      }

      Node $vsId ("CS vServer`n{0}" -f $r.CsVserver)
      Node $polId ("CS Policy`n{0}" -f $r.CsPolicy)
      Node $actId ("CS Action`n{0}" -f $r.CsAction)
      Edge $vsId $polId $prioLabel
      Edge $polId $actId "action"

      if ($lbId) {
        Node $lbId ("LB vServer`n{0}" -f $r.TargetLbVserver)
        Edge $actId $lbId "target"
        Add-LbTargets $r.TargetLbVserver
      }
    }
  } elseif ($entrypoint.Type -eq "LB vServer") {
    Add-LbTargets $entrypoint.Name
  }

  $lines.Add("}")
  Out-FileUtf8NoBom -Path $dotPath -Content ($lines -join "`r`n")
  return $dotPath
}

function Write-FullFlowDot {
  param(
    [Parameter(Mandatory=$true)]$m,
    [Parameter(Mandatory=$true)]$entrypoint,
    [Parameter(Mandatory=$true)][string]$baseName,
    [Parameter(Mandatory=$true)][string]$dir,
    [Parameter(Mandatory=$true)]$csFlows
  )

  $dotPath = Join-Path $dir ($baseName + ".flow.dot")
  $backendLookup = Get-BackendLookup -m $m

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("digraph netscaler {")
  $lines.Add("  rankdir=LR;")
  $lines.Add('  node [shape=box, fontsize=10];')
  $lines.Add('  edge [fontsize=9];')
  $lines.Add(('  label="Flow (migration-focused): {0}"; labelloc="t"; fontsize=18;' -f $baseName))

  $seen = @{}

  function Node($id, $label) {
    if ($seen.ContainsKey($id)) { return }
    $seen[$id] = $true
    $safe = ($label -replace '"','\"')
    $lines.Add(("  {0} [label=""{1}""];" -f $id, $safe))
  }
  function Edge($from, $to, $label) {
    $safe = ($label -replace '"','\"')
    $lines.Add(("  {0} -> {1} [label=""{2}""];" -f $from, $to, $safe))
  }
  function Id($prefix, $name) {
    return (($prefix + "_" + ($name -replace '[^a-zA-Z0-9_]', '_')))
  }
  function Add-LbTargets([string]$lbName) {
    if (-not $lbName) { return }
    $lbId = Id "lb" $lbName
    Node $lbId ("LB vServer`n{0}" -f $lbName)
    $targets = if ($backendLookup.LbTargets.ContainsKey($lbName)) { @($backendLookup.LbTargets[$lbName]) } else { @() }
    foreach ($t in $targets) {
      if ($m.ServiceGroup.ContainsKey($t)) {
        $sgId = Id "sg" $t
        Node $sgId ("Service Group`n{0}" -f $t)
        Edge $lbId $sgId "backend"
        if ($backendLookup.ServiceGroupMembers.ContainsKey($t)) {
          foreach ($member in @($backendLookup.ServiceGroupMembers[$t])) {
            $memId = Id "member" ($t + "_" + $member)
            Node $memId ("Member`n{0}" -f $member)
            Edge $sgId $memId "member"
          }
        }
        if ($backendLookup.ServiceGroupMonitors.ContainsKey($t)) {
          foreach ($mon in @($backendLookup.ServiceGroupMonitors[$t])) {
            $monId = Id "mon" ($t + "_" + $mon)
            Node $monId ("Monitor`n{0}" -f $mon)
            Edge $sgId $monId "monitor"
          }
        }
      } elseif ($m.Service.ContainsKey($t)) {
        $svcId = Id "svc" $t
        Node $svcId ("Service`n{0}" -f $t)
        Edge $lbId $svcId "backend"
      } else {
        $unkId = Id "backend" $t
        Node $unkId ("Backend`n{0}" -f $t)
        Edge $lbId $unkId "backend"
      }
    }
  }

  foreach ($r in @($csFlows)) {
    $vsId = Id "cs" $r.CsVserver
    $polId= Id "csp" $r.CsPolicy
    $actId= Id "csa" $r.CsAction
    $lbId = if ($r.TargetLbVserver) { Id "lb" $r.TargetLbVserver } else { $null }
    $prioLabel = if ($r.Source -eq "label") {
      "vs={0},pol={1}" -f $r.VserverPriority, $r.PolicyPriority
    } else {
      "prio={0}" -f $r.VserverPriority
    }

    Node $vsId ("CS vServer`n{0}" -f $r.CsVserver)
    Node $polId ("CS Policy`n{0}" -f $r.CsPolicy)
    Node $actId ("CS Action`n{0}" -f $r.CsAction)
    Edge $vsId $polId $prioLabel
    Edge $polId $actId "action"

    if ($lbId) {
      Node $lbId ("LB vServer`n{0}" -f $r.TargetLbVserver)
      Edge $actId $lbId "target"
      Add-LbTargets $r.TargetLbVserver
    }
  }

  $lbInUse = @{}
  foreach ($lbName in @($backendLookup.LbTargets.Keys)) { $lbInUse[$lbName] = $true }
  foreach ($r in @($csFlows)) {
    if ($r.TargetLbVserver) { $lbInUse[$r.TargetLbVserver] = $true }
  }
  foreach ($lbName in @($lbInUse.Keys)) { Add-LbTargets $lbName }

  # Global responder/rewrite callouts (not drawn to every vserver; just note)
  $globResp = @($m.Bindings | Where-Object { $_.TargetType -eq "Global" -and $_.Feature -eq "Responder" })
  $globRw   = @($m.Bindings | Where-Object { $_.TargetType -eq "Global" -and $_.Feature -eq "Rewrite" })
  if ($globResp.Count -gt 0 -or $globRw.Count -gt 0) {
    $gId = "global_policies"
    Node $gId "Global Policies (affect broad traffic)"
    if ($globResp.Count -gt 0) { Edge $gId $gId ("Responder global binds: {0}" -f $globResp.Count) }
    if ($globRw.Count -gt 0) { Edge $gId $gId ("Rewrite global binds: {0}" -f $globRw.Count) }
  }

  $lines.Add("}")
  Out-FileUtf8NoBom -Path $dotPath -Content ($lines -join "`r`n")
  return $dotPath
}

# ---------------------------
# HTML report writer (migration-centric)
# ---------------------------
function Write-Report {
  param(
    [Parameter(Mandatory=$true)]$m,
    [Parameter(Mandatory=$true)][string]$reportTitle,
    [Parameter(Mandatory=$true)][string]$baseName,
    [Parameter(Mandatory=$true)][string]$reportFileName,
    [Parameter(Mandatory=$true)][string]$dir,
    [Parameter(Mandatory=$true)]$csFlows,
    [Parameter(Mandatory=$true)]$respTable,
    [Parameter(Mandatory=$true)]$rwTable,
    [Parameter(Mandatory=$true)]$backend,
    [Parameter(Mandatory=$true)]$strays,
    [Parameter(Mandatory=$true)]$entrypoints,
    [Parameter(Mandatory=$true)]$entrypointFlows,
    [string]$flowDot,
    [string]$flowGraphic
  )

  Ensure-Dir $dir
  if ($null -eq $entrypoints) { $entrypoints = @() }
  if ($null -eq $entrypointFlows) { $entrypointFlows = @{} }

  $htmlPath = Join-Path $dir $reportFileName
  $csCsv    = Join-Path $dir ($baseName + ".csflows.csv")
  $respCsv  = Join-Path $dir ($baseName + ".responder.csv")
  $rwCsv    = Join-Path $dir ($baseName + ".rewrite.csv")
  $lbCsv    = Join-Path $dir ($baseName + ".lb-backend.csv")
  $sgCsv    = Join-Path $dir ($baseName + ".servicegroup-expansion.csv")
  $strayCsv = Join-Path $dir ($baseName + ".strays.csv")

  @($csFlows)    | Export-Csv -NoTypeInformation -Path $csCsv -Encoding UTF8
  @($respTable)  | Export-Csv -NoTypeInformation -Path $respCsv -Encoding UTF8
  @($rwTable)    | Export-Csv -NoTypeInformation -Path $rwCsv -Encoding UTF8
  @($backend.LbToBackend) | Export-Csv -NoTypeInformation -Path $lbCsv -Encoding UTF8
  @($backend.ServiceGroupExpansion) | Export-Csv -NoTypeInformation -Path $sgCsv -Encoding UTF8
  @($strays)     | Export-Csv -NoTypeInformation -Path $strayCsv -Encoding UTF8

  $globResp = @($m.Bindings | Where-Object { $_.TargetType -eq "Global" -and $_.Feature -eq "Responder" } | Sort-Object Priority, PolicyName)
  $globRw   = @($m.Bindings | Where-Object { $_.TargetType -eq "Global" -and $_.Feature -eq "Rewrite" } | Sort-Object Priority, PolicyName)

  $flowLink = ""
  if ($flowGraphic) { $flowLink = "<p><b>Flow graphic:</b> <a href=""$flowGraphic"">$([IO.Path]::GetFileName($flowGraphic))</a></p>" }
  elseif ($flowDot) { $flowLink = "<p><b>Flow DOT:</b> <a href=""$flowDot"">$([IO.Path]::GetFileName($flowDot))</a></p>" }

  $missingDefs = @($strays | Where-Object { $_.Reason -like "Referenced but not defined*" })
  $unusedDefs  = @($strays | Where-Object { $_.Reason -like "Defined but not *" })
  $missingActions = @($strays | Where-Object { $_.Type -like "*Action" -and $_.Reason -like "Referenced but not defined*" })

  $summary = [pscustomobject]@{
    Entrypoints = @($entrypoints).Count
    CsFlows = @($csFlows).Count
    ResponderBindings = @($respTable).Count
    RewriteBindings = @($rwTable).Count
    LbBackends = @($backend.LbToBackend).Count
    StrayArtifacts = @($strays).Count
    MissingDefinitions = @($missingDefs).Count
    UnusedDefinitions = @($unusedDefs).Count
    MissingActions = @($missingActions).Count
  }

  $summaryCards = @(
    [pscustomobject]@{ Label="Entry Points"; Value=$summary.Entrypoints },
    [pscustomobject]@{ Label="CS Flows"; Value=$summary.CsFlows },
    [pscustomobject]@{ Label="Responder Bindings"; Value=$summary.ResponderBindings },
    [pscustomobject]@{ Label="Rewrite Bindings"; Value=$summary.RewriteBindings },
    [pscustomobject]@{ Label="LB Backends"; Value=$summary.LbBackends },
    [pscustomobject]@{ Label="Stray Artifacts"; Value=$summary.StrayArtifacts }
  )

  $chartMax = 1
  foreach ($c in $summaryCards) { if ($c.Value -gt $chartMax) { $chartMax = $c.Value } }
  $chartRows = ($summaryCards | ForEach-Object {
    $pct = [math]::Round(($_.Value / $chartMax) * 100, 0)
    "<div class=""chart-row""><span>$($_.Label)</span><div class=""bar""><div class=""bar-fill"" style=""width:$pct%""></div></div><strong>$($_.Value)</strong></div>"
  }) -join "`r`n"

  $entrypointRows = @($entrypoints | Sort-Object Type, Name)
  $entrypointLinks = @($entrypoints | Sort-Object Type, Name | ForEach-Object {
    $key = "{0}::{1}" -f $_.Type, $_.Name
    $diagram = if ($entrypointFlows.ContainsKey($key)) { $entrypointFlows[$key] } else { "" }
    if ($diagram) { "<li><a href=""$diagram"">$($_.Type) - $($_.Name)</a></li>" }
  })

  $html = @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>$reportTitle - NetScaler Migration Report</title>
  <style>
    :root { color-scheme: light; }
    body { font-family: "Segoe UI", Arial, sans-serif; margin: 0; background: #f7f9fc; color: #1b1f23; }
    header { background: linear-gradient(120deg, #0a4ea3, #2d7dd2); color: #fff; padding: 28px 32px; }
    header h1 { margin: 0 0 6px 0; font-size: 26px; }
    header p { margin: 0; opacity: 0.9; }
    main { padding: 24px 32px 40px; }
    section { background: #fff; border-radius: 10px; padding: 18px 20px; margin: 0 0 18px 0; box-shadow: 0 2px 6px rgba(0,0,0,0.08); }
    h2 { margin-top: 0; font-size: 20px; }
    h3 { margin-bottom: 6px; }
    table { border-collapse: collapse; width: 100%; margin: 12px 0 18px 0; }
    th, td { border: 1px solid #e4e7eb; padding: 8px 10px; vertical-align: top; font-size: 13px; }
    th { background: #f0f3f8; text-align: left; }
    .small { color: #586069; font-size: 12px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
    .card { background: #f8fafc; border: 1px solid #e4e7eb; border-radius: 8px; padding: 12px 14px; }
    .card strong { display: block; font-size: 18px; }
    .callout { background: #eef6ff; border-left: 4px solid #2d7dd2; padding: 12px 14px; border-radius: 6px; }
    .chart-row { display: grid; grid-template-columns: 160px 1fr 60px; gap: 10px; align-items: center; margin: 6px 0; }
    .bar { background: #e9edf2; border-radius: 10px; height: 10px; overflow: hidden; }
    .bar-fill { height: 10px; background: linear-gradient(90deg, #2d7dd2, #74b9ff); }
    .links a { margin-right: 12px; }
  </style>
</head>
<body>
  <header>
    <h1>$reportTitle - Migration Readiness Report</h1>
    <p>Source configuration: $($m.File)</p>
  </header>
  <main>

  <section class="callout">
    <b>How to use this report for migration</b>
    <ul>
      <li>Start with <b>Entry Points</b>.</li>
      <li>For each CS vServer, use <b>CS Routing Flows</b> to see where traffic goes.</li>
      <li>Use <b>Responder</b> and <b>Rewrite</b> sections to understand what is being modified/blocked/redirected (policy + rule + action definition).</li>
      <li>Use <b>LB Backends</b> to rebuild server pools and monitors.</li>
      <li>Review <b>Stray Artifacts</b> to clean up or confirm intent before migrating.</li>
    </ul>
  </section>

  <section>
    <h2>Migration Summary</h2>
    <p class="small">Use this section to quickly spot scope and potential cleanup needs.</p>
    <div class="grid">
      $((@($summaryCards) | ForEach-Object { "<div class=""card""><span>$($_.Label)</span><strong>$($_.Value)</strong></div>" }) -join "`r`n")
    </div>
    <div style="margin-top:12px;">
      $chartRows
    </div>
  </section>

  <section>
    <h2>Entry Points</h2>
    $((@($entrypointRows) | ConvertTo-Html -Fragment -PreContent "<div class=""small"">Entry-point diagrams show the policy/backend flow tied to each ingress.</div>"))
    <ul>
      $($entrypointLinks -join "`r`n")
    </ul>
  </section>

  <section>
    <h2>Global Bindings (High Impact)</h2>
    <p class="small">These policies can affect broad traffic scope. Validate intent before migrating.</p>
    <h3>Responder (global)</h3>
    $((@($globResp) | Select-Object Priority, PolicyName, BindType, Extra | ConvertTo-Html -Fragment))
    <h3>Rewrite (global)</h3>
    $((@($globRw) | Select-Object Priority, PolicyName, BindType, Extra | ConvertTo-Html -Fragment))
  </section>

  <section class="links">
    <h2>Overall Flow Diagram</h2>
    $flowLink
  </section>

  <section>
    <h2>CS Routing Flows (CS vServer → Policy → Action → Target LB vServer)</h2>
    <p class="small">This is the core “where does traffic go?” view.</p>
    $((@($csFlows) | ConvertTo-Html -Fragment))
  </section>

  <section>
    <h2>Responder (Bound Policy → Rule → Action Definition)</h2>
    <p class="small">This section explains what responder policies do by pairing policies with their actions.</p>
    $((@($respTable) | ConvertTo-Html -Fragment))
  </section>

  <section>
    <h2>Rewrite (Bound Policy → Rule → Action Definition)</h2>
    <p class="small">This section explains rewrite behavior by pairing policies with actions.</p>
    $((@($rwTable) | ConvertTo-Html -Fragment))
  </section>

  <section>
    <h2>LB Backends (LB vServer → Backend target)</h2>
    $((@($backend.LbToBackend) | ConvertTo-Html -Fragment))
  </section>

  <section>
    <h2>Service Group Expansion (Members + Monitors)</h2>
    $((@($backend.ServiceGroupExpansion) | ConvertTo-Html -Fragment))
  </section>

  <section>
    <h2>Stray Artifacts (Review Candidates)</h2>
    <p class="small">Likely unused, or missing from the provided config set. Confirm before migrating.</p>
    $((@($strays) | ConvertTo-Html -Fragment))
  </section>

  <section>
    <h2>Downloads</h2>
    <ul>
      <li><a href="$([IO.Path]::GetFileName($csCsv))">$([IO.Path]::GetFileName($csCsv))</a></li>
      <li><a href="$([IO.Path]::GetFileName($respCsv))">$([IO.Path]::GetFileName($respCsv))</a></li>
      <li><a href="$([IO.Path]::GetFileName($rwCsv))">$([IO.Path]::GetFileName($rwCsv))</a></li>
      <li><a href="$([IO.Path]::GetFileName($lbCsv))">$([IO.Path]::GetFileName($lbCsv))</a></li>
      <li><a href="$([IO.Path]::GetFileName($sgCsv))">$([IO.Path]::GetFileName($sgCsv))</a></li>
      <li><a href="$([IO.Path]::GetFileName($strayCsv))">$([IO.Path]::GetFileName($strayCsv))</a></li>
    </ul>
  </section>

  </main>
</body>
</html>
"@

  Out-FileUtf8NoBom -Path $htmlPath -Content $html
  return $htmlPath
}

# ---------------------------
# Main
# ---------------------------
# Normalize OutDir for predictable behavior
try {
  $OutDir = (Resolve-Path -LiteralPath $OutDir -ErrorAction Stop).Path
} catch {
  $OutDir = Join-Path (Get-Location).Path $OutDir
}

Ensure-Dir $OutDir
$reportBaseName = $VPXName
$reportDir = Join-Path $OutDir $VPXName
Ensure-Dir $reportDir

$dotExe = Find-DotExe -override $DotExePath
$renderWarn = @()

foreach ($m in $models) {
  $name = [IO.Path]::GetFileNameWithoutExtension($m.File)
  $dir  = Join-Path $perFileDir $name
  Ensure-Dir $dir

  $csFlows   = Get-CsFlows -m $m
  if ($null -eq $csFlows) { $csFlows = @() }
  $respTable = Get-ResponderTable -m $m
  if ($null -eq $respTable) { $respTable = @() }
  $rwTable   = Get-RewriteTable -m $m
  if ($null -eq $rwTable) { $rwTable = @() }
  $backend   = Get-BackendTable -m $m
  if ($null -eq $backend) { $backend = @() }
  $strays    = Get-StrayArtifacts -m $m
  if ($null -eq $strays) { $strays = @() }

  $flowDot = Write-FlowDot -m $m -baseName $name -dir $dir -csFlows $csFlows
  $flowGraphic = $null

  if (-not $SkipGraphRender -and $dotExe -and ($GraphFormat -ne 'dot')) {
    $flowGraphic = Render-GraphSafe -DotExe $dotExe -DotPath $flowDot -Format $GraphFormat
    if (-not $flowGraphic) { $renderWarn += "Render failed: $flowDot" }
  }

  $report = Write-Report -m $m -baseName $name -dir $dir -csFlows $csFlows -respTable $respTable -rwTable $rwTable -backend $backend -strays $strays -flowDot $flowDot -flowGraphic $flowGraphic

  $indexRows += [pscustomobject]@{
    File       = $m.File
    ReportHtml = $report
    Flow       = if ($flowGraphic) { $flowGraphic } else { $flowDot }
  }
}
$strays    = Get-StrayArtifacts -m $m
if ($null -eq $strays) { $strays = @() }
$entrypoints = Get-EntryPoints -m $m
if ($null -eq $entrypoints) { $entrypoints = @() }

$entrypointFlows = @{}
foreach ($ep in @($entrypoints)) {
  $safeName = Get-SafeFileName -Name ("{0}_{1}" -f $ep.Type, $ep.Name)
  $entryBase = $safeName
  $epDot = Write-EntryPointFlowDot -m $m -entrypoint $ep -baseName $entryBase -dir $reportDir -csFlows $csFlows
  $epGraphic = $null
  if (-not $SkipGraphRender -and $dotExe -and ($GraphFormat -ne 'dot')) {
    $epGraphic = Render-GraphSafe -DotExe $dotExe -DotPath $epDot -Format $GraphFormat
    if (-not $epGraphic) { $renderWarn += "Render failed: $epDot" }
  }
  $entrypointFlows["{0}::{1}" -f $ep.Type, $ep.Name] = if ($epGraphic) { [IO.Path]::GetFileName($epGraphic) } else { [IO.Path]::GetFileName($epDot) }
}
foreach ($p in $cm.CsPolicy.Keys)        { if ($cm.Refs.UsedCsPolicy.ContainsKey($p)) { Mark-Ref $cm "UsedCsAction" $cm.CsPolicy[$p].action } }
foreach ($p in $cm.ResponderPolicy.Keys) { if ($cm.Refs.UsedResponderPolicy.ContainsKey($p)) { Mark-Ref $cm "UsedResponderAction" $cm.ResponderPolicy[$p].action } }
foreach ($p in $cm.RewritePolicy.Keys)   { if ($cm.Refs.UsedRewritePolicy.ContainsKey($p)) { Mark-Ref $cm "UsedRewriteAction" $cm.RewritePolicy[$p].action } }

$combinedName = "ALL"
$csFlowsC   = Get-CsFlows -m $cm
if ($null -eq $csFlowsC) { $csFlowsC = @() }
$respTableC = Get-ResponderTable -m $cm
if ($null -eq $respTableC) { $respTableC = @() }
$rwTableC   = Get-RewriteTable -m $cm
if ($null -eq $rwTableC) { $rwTableC = @() }
$backendC   = Get-BackendTable -m $cm
if ($null -eq $backendC) { $backendC = @() }
$straysC    = Get-StrayArtifacts -m $cm
if ($null -eq $straysC) { $straysC = @() }
$flowDotC   = Write-FlowDot -m $cm -baseName $combinedName -dir $combinedDir -csFlows $csFlowsC
$flowGraphicC = $null

$flowBase = "{0}_Flow" -f (Get-SafeFileName -Name $reportBaseName)
$flowDot = Write-FullFlowDot -m $m -baseName $flowBase -dir $reportDir -csFlows $csFlows
$flowGraphic = $null
if (-not $SkipGraphRender -and $dotExe -and ($GraphFormat -ne 'dot')) {
  $flowGraphic = Render-GraphSafe -DotExe $dotExe -DotPath $flowDot -Format $GraphFormat
  if (-not $flowGraphic) { $renderWarn += "Render failed: $flowDot" }
}
$flowGraphicName = if ($flowGraphic) { [IO.Path]::GetFileName($flowGraphic) } else { $null }
$flowDotName = [IO.Path]::GetFileName($flowDot)

$reportFileName = "{0}_ConfigurationReport.html" -f $reportBaseName
$report = Write-Report -m $m -reportTitle $VPXName -baseName $reportBaseName -reportFileName $reportFileName -dir $reportDir -csFlows $csFlows -respTable $respTable -rwTable $rwTable -backend $backend -strays $strays -entrypoints $entrypoints -entrypointFlows $entrypointFlows -flowDot $flowDotName -flowGraphic $flowGraphicName

if (@($renderWarn).Count -gt 0) {
  Write-Warning ("Graph render warnings:`r`n" + ($renderWarn -join "`r`n"))
}

Write-Host ("Report directory: {0}" -f $reportDir)
Write-Host ("Report: {0}" -f (Join-Path $reportDir $reportFileName))
