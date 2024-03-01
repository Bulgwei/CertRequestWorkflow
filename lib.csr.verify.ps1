# ==============================================================================================
# THIS SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
# FITNESS FOR A PARTICULAR PURPOSE.
#
# This sample is not supported under any Microsoft standard support program or service. 
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for 
# any damages whatsoever (including, without limitation, damages for loss of business profits, 
# business interruption, loss of business information, or other pecuniary loss) arising out of 
# the use of or inability to use the sample or documentation, even if Microsoft has been advised 
# of the possibility of such damages.
# ==============================================================================================
#
# version 1.1
# dev'd by andreas.luy@microsoft.com
#
#
# custom Csr verification library. All automatic verifcation rule should be place here!
#
#


function check-DNSSubjectNames
{
    param(
        [Parameter(mandatory=$true)]$objSubject,
        [Parameter(mandatory=$true)]$objSAN
    )
    #
    # return data type: boolean
    #

    $found=$true
    if($objSubject.CN.length -gt 0){
        try{
            $Result=Resolve-DnsName $objSubject.CN.split("=")[1] -Server $global:DNSServer -ErrorAction Stop
            if($Result -match "failure"){$found=$false}
        }
        catch{$found=$false}
    }
    if($objSAN.count -gt 0){
        $found=$true
        foreach($SAN in $objSAN){
            if($SAN.Type -eq "DNS Name"){
                try{
                    $Result=Resolve-DnsName $SAN.SAN -Server $global:DNSServer -ErrorAction Stop
                    if($Result -match "failure"){$found=$false}
                }
                catch{$found=$false}
            }
        }
    }
    return $found
}

function RegEx-SubjectCheck
{
    param(
        [Parameter(mandatory=$true)]$objSubject
    )
    #
    # return data type: boolean
    #

    $passed=$false
    $passed=($objSubject -match "Contoso Inc") -and ($objSubject -match "@contoso.com") -and ($objSubject.CN -notmatch "\s+")
    return $passed
}

function RegEx-SANCheck
{
    param(
        [Parameter(mandatory=$true)]$objSAN
    )
    #
    # return data type: boolean
    #

    if($objSAN.count -gt 0){
        $passed=$true
        foreach($SAN in $objSAN){
            if(($SAN.SAN -notmatch ".contoso.com") -or ($SAN.SAN -match "\s+")){$passed=$false}
        }
    }
    return $passed
}

Function Reject-Csr
{
    param(
        [Parameter(mandatory=$true,Position=0)]
        [ValidateSet("KeyLength","Signature","RequestAttributes","SubjectName","CertTmpl","EKU","KeyUsage","SAN")] 
        [String]$Reason,
        [Parameter(mandatory=$false)] [String]$Info,
        [Parameter(mandatory=$true)] [String]$CsrName

    )


    switch ($Reason) {
        "Signature" {
            $Reasontxt = "Signature verification error!"
        }
        "KeyLength" {
            $Reasontxt = "KeyLength verification error!`n`rCsr Key Length: "+ $Info
        }
        "SubjectName" {
            $Reasontxt = "SubjectName compliance error!`n`SubjectName: "+ $Info
        }
        "SAN" {
            $Reasontxt = "Subject Alternative Name compliance error!`n`SubjectAltNames: "+ $Info
        }
        "EKU" {
            $Reasontxt = "Enhanced Key Usage verification error!`n`rCsr EKUs: "+ $Info
        }
        "KeyUsage" {
            $Reasontxt = "Key Usage violation error!`n`rCsr Key Usage: "+ $Info
        }
        "CertTmpl" {
            $Reasontxt = "Certificate Template error!`n` Certificate template in Csr: "+ $Info
        }
        "RequestAttributes" {
            $Reasontxt = "Request Attributes verification error!`n`rRequest Attributes in Csr: "+ $Info
        }
    }

    $EvtMsg = "Automatic Csr validation failed! Csr rejected`n`r"+$Reasontxt+"`n`rManually verify Csr`n`r"+$CsrName+"`n`rand take appropriate action!"
    Write-Eventlog $Global:EventLog -Source $Global:EventSource -EventID 2000 -EntryType Warning -Message $EvtMsg

}

Function Pass-CsrVerification
{
    param(
        [Parameter(mandatory=$true)] $Csr,
        [Parameter(mandatory=$true)] [String]$CsrName

    )
    $Result=$true

    # sample verification rules

    if($csr.KeyLength -lt 2048){ Reject-Csr -reason "KeyLength" -Info ([String]$csr.KeyLength) -CsrName $CsrName; $Result=$false }
    if(!$csr.SignatureMatch){ Reject-Csr -Reason "Signature"-CsrName $CsrName; $Result=$false }

    # your rules come here


    return $Result
}


