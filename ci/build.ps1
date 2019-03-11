$nugetPath = ''
$nugetApiKey = ''

$projSrc = "$PSScriptRoot\..\src"
$bin = "$projSrc\bin"
$projfile = "$projSrc\CoreSaml2Utils.csproj"

Remove-Item "$bin\*" -Recurse -Force

dotnet build $projfile -c Release

dotnet pack $projfile -c Release --include-symbols --no-build

$pkg = Get-ChildItem -Path "$bin\Release\*symbols.nupkg" | Select-Object -first 1

if (!($nugetPath -eq '')) {
    if (!($nugetApiKey -eq '')) {
        dotnet nuget push $pkg -s $nugetPath -k $nugetApiKey
    }
    else {
        dotnet nuget push $pkg -s $nugetPath
    }
    
    try {
        nuget locals all -clear
    }
    catch {
    
    }
}