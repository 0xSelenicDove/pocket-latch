param([ValidateSet('x64', 'ARM64')][string]$Platform = 'x64')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$msbuild = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) { throw 'Visual Studio with C# UWP build tools is required on the build machine only.' }
$packagePrefix = 'CdfProbe'
$subject = 'CN=PocketLatch'
$project = Join-Path $root 'CdfProbe.sln'
$instructions = Join-Path $PSScriptRoot 'INSTALL.txt'
    & dotnet publish (Join-Path $root 'BluetoothHost\BluetoothHost.csproj') -c Release -r "win-$($Platform.ToLower())" --self-contained true -o (Join-Path $root 'CdfProbe\BluetoothHost')
    if ($LASTEXITCODE -ne 0) { throw 'Bluetooth host build failed.' }
    $hostRoot = Join-Path $root 'CdfProbe\BluetoothHost'
    $payload = @('<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><Target Name="IncludeBluetoothHost" AfterTargets="BuildNativePackage"><ItemGroup>')
    foreach ($file in Get-ChildItem $hostRoot -Recurse -File) {
        $source = [System.Security.SecurityElement]::Escape($file.FullName)
        $target = [System.Security.SecurityElement]::Escape('BluetoothHost\' + $file.FullName.Substring($hostRoot.Length + 1))
        $payload += "<AppxPackagePayload Include=`"$source`"><TargetPath>$target</TargetPath></AppxPackagePayload>"
    }
    $payload += '</ItemGroup></Target></Project>'
    $payload | Set-Content (Join-Path $root 'CdfProbe\BluetoothHost.Payload.targets') -Encoding UTF8

$output = Join-Path $root "artifacts\$packagePrefix-$Platform"
New-Item $output -ItemType Directory -Force | Out-Null

# Short-lived test signing identity. The private key remains on this build machine.
$cert = New-SelfSignedCertificate -Type Custom -Subject $subject `
    -FriendlyName 'PocketLatch community signing' -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256 -KeyUsage DigitalSignature -CertStoreLocation 'Cert:\CurrentUser\My' `
    -NotAfter (Get-Date).AddDays(90) `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
try {
    & $msbuild $project /restore /t:Build /m /verbosity:minimal `
        '/p:TargetPlatformMinVersion=10.0.17763.0' '/p:Configuration=Release' "/p:Platform=$Platform" '/p:TargetPlatformVersion=10.0.19041.0' `
        '/p:BuildSideloadPackage=true' '/p:UapAppxPackageBuildMode=SideloadOnly' `
        '/p:AppxBundle=Never' '/p:AppxPackageSigningEnabled=true' `
        "/p:PackageCertificateThumbprint=$($cert.Thumbprint)" "/p:AppxPackageDir=$output\" `
        "/bl:$output\build.binlog"
    if ($LASTEXITCODE -ne 0) { throw "MSBuild failed: $LASTEXITCODE" }

    $package = @(Get-ChildItem $output -Recurse -File | Where-Object {
        $_.Extension -in '.appx', '.msix' -and $_.Name -like "$packagePrefix*"
    })
    if ($package.Count -ne 1) { throw "Expected one probe APPX/MSIX; found $($package.Count)." }
    $package = $package[0]
    $folder = $package.Directory.FullName
    if (-not (Test-Path (Join-Path $folder 'Add-AppDevPackage.ps1'))) { throw 'Generated sideload installer missing.' }
    if (-not (Test-Path (Join-Path $folder 'Dependencies'))) { throw 'Runtime dependency packages missing.' }
    Export-Certificate -Cert $cert -FilePath (Join-Path $folder ($package.BaseName + '.cer')) -Force | Out-Null
    Copy-Item (Join-Path $PSScriptRoot 'Install.cmd') $folder
    Copy-Item $instructions (Join-Path $folder 'INSTALL.txt')
    # Validate the signature with the build certificate trusted only on this disposable runner.
    $trusted = Import-Certificate -FilePath (Join-Path $folder ($package.BaseName + '.cer')) -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople'
    try {
        $signtool = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe'
        & $signtool verify /pa /v $package.FullName
        if ($LASTEXITCODE -ne 0) { throw 'Package signature verification failed.' }
    } finally { Remove-Item $trusted.PSPath }

    $hash = (Get-FileHash $package.FullName -Algorithm SHA256).Hash
    @("Architecture: $Platform", "Package: $($package.Name)", "Package SHA256: $hash", `
        "Certificate SHA1 thumbprint: $($cert.Thumbprint)", "Certificate expiry: $($cert.NotAfter.ToUniversalTime().ToString('O'))", `
        "Source commit: $env:GITHUB_SHA", 'Build: Release UWP, with bundled runtime dependencies') |
        Set-Content (Join-Path $folder 'BUILD-INFO.txt')
    if (Get-ChildItem $folder -Recurse -Filter '*.pfx') { throw 'Private signing key must not be distributed.' }
    $zip = Join-Path $root "artifacts\$packagePrefix-$Platform-install.zip"
    Compress-Archive -Path (Join-Path $folder '*') -DestinationPath $zip -Force
    Write-Host "INSTALLER: $zip"
    Write-Host "SHA256: $((Get-FileHash $zip -Algorithm SHA256).Hash)"
} finally {
    Remove-Item $cert.PSPath
}
