[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$UsePublicIP
)
try {

    Start-Transcript -Path C:\cfn\log\$($MyInvocation.MyCommand.Name).log -Append

    $rootCAparams = @{
      Subject = "CN=PlateSpin CA, C=US, ST=Utah, L=Provo, O=Micro Focus Ltd., OU=PlateSpin"
      TextExtension = @("2.5.29.19 ={critical} {text}ca=1")
      KeyLength = 2048
      KeyAlgorithm = 'RSA'
      HashAlgorithm = 'SHA256'
      KeyExportPolicy = 'Exportable'
      NotAfter = (Get-Date).AddYears(5)
      CertStoreLocation = 'Cert:\LocalMachine\My'
      KeyUsage = 'CertSign','CRLSign'
    }

    $rootCA = New-SelfSignedCertificate @rootCAparams
    $rootCA

    $CertStore = New-Object -TypeName `
      System.Security.Cryptography.X509Certificates.X509Store(
      [System.Security.Cryptography.X509Certificates.StoreName]::Root,
      'LocalMachine')
    $CertStore.open('MaxAllowed')
    $CertStore.add($rootCA)
    $CertStore.close()

    Export-Certificate -Cert $rootCA -FilePath c:\cfn\PlateSpinCA.cer

    Set-Variable -Name "timetolive" -Value 600 -Option constant 
    $tokenuri = "http://169.254.169.254/latest/api/token"
    $token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds"=$timetolive} -URI $tokenuri -Method put

    $dns = ((Invoke-WebRequest -Headers @{"X-aws-ec2-metadata-token"=$token} -Uri http://169.254.169.254/latest/meta-data/local-hostname -UseBasicParsing).RawContent -split "`n")[-1]
    $ip = ((Invoke-WebRequest -Headers @{"X-aws-ec2-metadata-token"=$token} -Uri http://169.254.169.254/latest/meta-data/local-ipv4 -UseBasicParsing).RawContent -split "`n")[-1]
    if ($UsePublicIP) {
        $publicdns = ((Invoke-WebRequest -Headers @{"X-aws-ec2-metadata-token"=$token} -Uri http://169.254.169.254/latest/meta-data/public-hostname -UseBasicParsing).RawContent -split "`n")[-1]
        $publicip = ((Invoke-WebRequest -Headers @{"X-aws-ec2-metadata-token"=$token} -Uri http://169.254.169.254/latest/meta-data/public-ipv4 -UseBasicParsing).RawContent -split "`n")[-1]
        $textExten = @("2.5.29.17={text}IpAddress = $ip&IpAddress = $publicip&IpAddress = '127.0.0.1'&IpAddress = '::1'&DNS = $dns&DNS = $publicdns&DNS = 'localhost'")
    } else {
        $textExten = @("2.5.29.17={text}IpAddress = $ip&IpAddress = '127.0.0.1'&IpAddress = '::1'&DNS = $dns&DNS = 'localhost'")
    }    
    $params = @{
      Subject = "CN=PlateSpin Migrate, C=US, ST=Utah, L=Provo, O=PlateSpin"
      TextExtension = $textExten
      Signer = $rootCA 
      KeyLength = 2048
      KeyAlgorithm = 'RSA'
      HashAlgorithm = 'SHA256'
      KeyExportPolicy = 'Exportable'
      NotAfter = (Get-Date).AddYears(2)
      CertStoreLocation = 'Cert:\LocalMachine\My'
      FriendlyName = 'Signed by PlateSpin CA'
    }

    $ServerCert = New-SelfSignedCertificate @params
    $ServerCert


    (Get-WebBinding -Name "Default Web Site" -Port 443 -Protocol "https").AddSslCertificate($ServerCert.Thumbprint, "My") 
   
}
catch {
    Write-Verbose "catch: $_"
    $_ | Write-AWSQuickStartException
}
