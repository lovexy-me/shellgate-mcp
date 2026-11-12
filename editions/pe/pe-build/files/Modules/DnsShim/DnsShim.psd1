@{
    RootModule        = 'DnsShim.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '5b0e7f8e-3c51-4c55-9a43-7d2f1a6b9c21'
    Description       = 'WinPE stand-in for Resolve-DnsName (system resolver, A/AAAA only)'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Resolve-DnsName')
}
