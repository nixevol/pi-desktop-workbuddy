<#
.SYNOPSIS
  Pack this plugin into a .piplug the host will accept.

.DESCRIPTION
  PI-Desktop parses a .piplug itself, walking local file headers in order
  (crates/host-core/src/plugins/install.rs) and rejecting the whole package the
  moment an entry's compression method is not 0:

      if method != 0 {
          bail!("PLUGIN_INVALID: only store-compressed piplug supported");
      }

  So the archive must be built with compression *disabled*. `Compress-Archive`
  always deflates, which is why it produces a package the host refuses; the
  .NET ZipArchive below is created with CompressionLevel.NoCompression instead.

  Writing through ZipArchive also keeps the local header's compressed and
  uncompressed sizes in step and omits the optional data descriptor, whose
  signature (0x08074b50) would otherwise be read as the next entry's header.

  Run from the plugin root:  pwsh -File tools\pack.ps1
#>
[CmdletBinding()]
param(
  [string]$Output
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$version = (Get-Content (Join-Path $root 'manifest.json') -Raw | ConvertFrom-Json).version
if (-not $Output) {
  $Output = Join-Path $root ('dist/local.pi-desktop-workbuddy-{0}.piplug' -f $version)
}

# Everything the plugin needs at run time, plus the sources it was built from.
$include = @('manifest.json', 'main.js', 'package.json', 'package-lock.json', 'build.mjs', 'README.md', 'lib', 'renderer', 'src')

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ('piplug-stage-' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force -Path $stage | Out-Null
try {
  foreach ($item in $include) {
    $from = Join-Path $root $item
    if (-not (Test-Path $from)) { throw "missing required item: $item" }
    Copy-Item $from (Join-Path $stage $item) -Recurse -Force
  }

  New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null
  Remove-Item $Output -Force -ErrorAction SilentlyContinue

  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem

  $stageRoot = (Resolve-Path $stage).Path
  $stream = [System.IO.File]::Open($Output, [System.IO.FileMode]::Create)
  $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
  try {
    foreach ($file in (Get-ChildItem $stage -Recurse -File | Sort-Object FullName)) {
      $name = $file.FullName.Substring($stageRoot.Length + 1).Replace('\', '/')
      $entry = $zip.CreateEntry($name, [System.IO.Compression.CompressionLevel]::NoCompression)
      $entryStream = $entry.Open()
      try {
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        $entryStream.Write($bytes, 0, $bytes.Length)
      } finally { $entryStream.Dispose() }
    }
  } finally {
    $zip.Dispose()
    $stream.Dispose()
  }

  # Re-read the archive the way the host does, so a bad package fails here.
  $bytes = [System.IO.File]::ReadAllBytes($Output)
  $offset = 0; $count = 0
  while ($offset + 30 -le $bytes.Length) {
    $sig = [System.BitConverter]::ToUInt32($bytes, $offset)
    if ($sig -eq 0x02014b50 -or $sig -eq 0x06054b50) { break }
    if ($sig -ne 0x04034b50) { throw ('bad zip local header at offset {0}' -f $offset) }
    $method = [System.BitConverter]::ToUInt16($bytes, $offset + 8)
    if ($method -ne 0) { throw 'only store-compressed piplug supported (method {0})' -f $method }
    $compSize = [System.BitConverter]::ToUInt32($bytes, $offset + 18)
    $nameLen = [System.BitConverter]::ToUInt16($bytes, $offset + 26)
    $extraLen = [System.BitConverter]::ToUInt16($bytes, $offset + 28)
    $count++
    $offset = $offset + 30 + $nameLen + $extraLen + $compSize
  }

  $hash = (Get-FileHash $Output -Algorithm SHA256).Hash.ToLower()
  $size = [math]::Round((Get-Item $Output).Length / 1KB, 1)
  Write-Host ("packed {0} ({1} files, {2} KB, store-only)" -f $Output, $count, $size)
  Write-Host ("sha256 {0}" -f $hash)
} finally {
  Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}
