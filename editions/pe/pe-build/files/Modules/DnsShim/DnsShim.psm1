# WinPE has no DnsClient module (and no nslookup.exe). This is a small stand-in for the common
# cases: Resolve-DnsName <name> [-Type A|AAAA] through the system resolver. -Server and record
# types other than A/AAAA are not supported and say so instead of returning wrong answers.
function Resolve-DnsName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Name,
        [Parameter(Position = 1)][string]$Type = 'A_AAAA',
        [string]$Server,
        [switch]$DnsOnly, [switch]$NoHostsFile, [switch]$QuickTimeout
    )
    process {
        if ($Server) { throw "Resolve-DnsName (WinPE shim): -Server is not supported; only the system resolver is available." }
        $t = $Type.ToUpperInvariant()
        if ($t -notin 'A', 'AAAA', 'A_AAAA', 'ALL') { throw "Resolve-DnsName (WinPE shim): record type $Type is not supported (A, AAAA only)." }
        foreach ($ip in [System.Net.Dns]::GetHostAddresses($Name)) {
            $rt = if ($ip.AddressFamily -eq 'InterNetworkV6') { 'AAAA' } else { 'A' }
            if ($t -in 'A', 'AAAA' -and $rt -ne $t) { continue }
            [pscustomobject]@{ Name = $Name; Type = $rt; TTL = $null; Section = 'Answer'; IPAddress = $ip.IPAddressToString }
        }
    }
}
Export-ModuleMember -Function Resolve-DnsName
