$packageArgs = @{
  packageName = 'legacytool'
  fileType    = 'exe'
  url         = 'http://example.com/legacy-setup.exe'
  silentArgs  = '/S'
}
Install-ChocolateyPackage @packageArgs
