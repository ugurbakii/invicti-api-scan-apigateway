# $File = "C:\cred.dat"
# $Password = "testPass" | ConvertTo-SecureString -AsPlainText -Force
# $Password | ConvertFrom-SecureString | Out-File $File

# $File = "C:\credenc.dat"
# $secureStr= Get-Content $File | ConvertTo-SecureString
# $password2 = (New-Object PSCredential "user",$secureStr).GetNetworkCredential().Password
# Write-Output $password2

Add-Type -Path "C:\oracle\product\12.2.0\client_1\odp.net\managed\common\Oracle.ManagedDAtaAccess.dll"

$username = "APIG"
$secureStr = Get-Content "C:\Powershell\Secure\apigate_uat.dat" | ConvertTo-SecureString
# $password = (New-Object PSCredential "user",$secureStr).GetNetworkCredential().Password
$password = (New-Object PSCredential "user", $secureStr).GetNetworkCredential().Password
$datasource = "APIGATE_UAT"

$query = "select * from SAZ";

$connectionString = 'User Id=' + $username + ';Password=' + $password + ';Data Source=' + $datasource
$connection = New-Object Oracle.ManagedDataAccess.Client.OracleConnection($connectionString)
$connection.open()
$command = New-Object Oracle.ManagedDataAccess.Client.OracleCommand
$command.Connection = $connection
$command.CommandText = $query
$ds = New-Object system.Data.DataSet
$da = New-Object Oracle.ManagedDataAccess.Client.OracleDataAdapter($command)
[void]$da.fill($ds)

If (Test-Path -Path 'C:\saz\raw' ) {
    Remove-Item 'C:\saz\raw' -Recurse
    New-Item -Path 'C:\saz\raw' -ItemType Directory
}
Else {
    New-Item -Path 'C:\saz\raw' -ItemType Directory
}
$list = @("a-im:", "accept:", "accept-charset:", "accept-datetime:", "accept-encoding:","apikey:", "accept-language:","domainname:", "access-control-request-method:", "access-control-request-headers[12]:", "authorization:", "cache-control:", "connection:", "content-encoding:", "content-length:", "content-md5:", "content-type:", "cookie:", "date:", "expect:", "forwarded:", "from:", "host:", "http2-settings:", "if-match:", "if-modified-since:", "if-none-match:", "if-range:", "if-unmodified-since:", "max-forwards:", "origin[12]:", "pragma:", "prefer:", "proxy-authorization:", "range:", "referer [sic]:", "te:", "trailer:", "transfer-encoding:", "user-agent:", "upgrade:", "via:", "warning:", "grade-insecure-requests:", "x-requested-with:", "dnt:", "x-forwarded-for:", "x-forwarded-host:", "x-forwarded-proto:", "front-end-https:", "x-http-method-override:", "x-att-deviceid:", "x-wap-profile:", "proxy-connection:", "x-uidh:", "x-csrf-token:", "x-request-id,:", "x-correlation-id,:", "save-data:", "sec-gpc:", "accept-ch:", "access-control-allow-origin,:", "access-control-allow-credentials,:", "access-control-expose-headers,:", "access-control-max-age,:", "access-control-allow-methods,:", "access-control-allow-headers:", "accept-patch:", "accept-ranges:", "age:", "allow:", "alt-svc:", "cache-control:", "connection:", "content-disposition:", "content-encoding:", "content-language:", "content-length:", "content-location:", "content-md5:", "content-range:", "content-type:", "date:", "delta-base:", "etag:", "expires:", "im:", "last-modified:", "link:", "location:", "p3p:", "pragma:", "preference-applied:", "proxy-authenticate:", "public-key-pins:", "retry-after:", "server:", "set-cookie:", "strict-transport-security:", "trailer:", "transfer-encoding:", "tk:", "upgrade:", "vary:", "via:", "warning:", "www-authenticate:", "x-frame-options:", "content-security-policy,:", "x-content-security-policy,:", "x-webkit-csp:", "expect-ct:", "nel:", "permissions-policy:", "refresh:", "report-to:", "status:", "timing-allow-origin:", "x-content-duration:", "x-content-type-options:", "x-powered-by:", "x-redirect-by:", "x-request-id, x-correlation-id:", "x-ua-compatible:", "x-xss-protection:","origin:", "referer:","sec-fetch-mode:","sec-fetch-site:","x-api-requestid:","x-forwarded-port:","sec-fetch-dest:","sec-fetch-mode","sec-ch-ua-mobile:","remote_addr:","keysecret:","traceparent:","client-ip:","postman-token:","sap-passport:","sap-language:","sap-srt_id:","soapaction:","sap-srt_id:","sec-ch-ua:","x-company-id:","password:","username:","pragma:","x-ruxit-forwarded-for:","x-instana-l:","elastic-apm-traceparent:", "request-id:", "x-newrelic-id:", "x-newrelic-transaction:", "ecid-context:", "x-instana-s:","x-instana-t:","tracestate:","singularityheader:","domainname:","l7-key-passphrase:","domain.functioncode:","domain.operationcode:")

$nameCount = 0
$user = "basicuser"
$pass = "basicpass"
$pair = "${user}:${pass}"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$token = [System.Convert]::ToBase64String($bytes)
$apikey = ''
$keysecret = ''
$clientip = ''
$content = ''
foreach ($row IN $ds.Tables[0].Rows) {
    $nameCount ++

    $reqFile = "C:\saz\raw\{0}_c.txt" -f $nameCount
    $respFile = "C:\saz\raw\{0}_s.txt" -f $nameCount

    if ($row['REQ']) {
        $CharArray = $row['REQ'].Split([Environment]::NewLine, [System.StringSplitOptions]::RemoveEmptyEntries)
        Write-output $CharArray
        $postWord = $CharArray[0].Split(" ")
        $postWord[0].Replace("[", "").Replace("]", " ") + "https://apigate.domain.com" + $postWord[1] + " HTTP/1.1"  | Out-File -FilePath  $reqFile -Encoding ASCII
        $header = $CharArray[1].Replace('headers: ', '').ToLower().Split(",")

        $actualHeaderList = New-Object System.Collections.ArrayList
        for ($i = 0; $i -le $header.length; $i++) {
            if ($header[$i]) {
                $keyTrim = $header[$i].Trim()
                if ($i -eq $header.Length - 1) {
                    $actualHeaderList.Add($keyTrim)
                }
                else {     
                    $next = $header[$i + 1].Trim()
                    $startWith = $false
                    foreach ($item in $list) {
                        if ($next.StartsWith($item)) {
                            $startWith = $true
                        }
                    }
                    if ($startWith) {
                        $actualHeaderList.Add($keyTrim)
                    }
                    else {
                        $newKey = $keyTrim;
                        for ($z = $i + 1; $z -le $header.length; $z++) {
                            if ($header[$z]) {
                                $next = $header[$z].Trim()
                                $startWith2 = $false
                                foreach ($item in $list) {
                                    if ($next.StartsWith($item)) {
                                        $startWith2 = $true
                                    }
                                }
                                if (!$startWith2) {
                                    $newKey = $newKey + "," + $next;
                                    $i++;
                                }
                                else {
                                    break
                                }
                            }
                        }
                        $actualHeaderList.Add($newKey)
                    }
                }
            }
        }

         foreach ($rowStrItem in $actualHeaderList) {
            $rowStr = $rowStrItem.Trim()
            $rowStr = $rowStr.Replace('localhost', 'apigate.domain.com')
			$rowStr = $rowStr.Replace('akosbuat.domain.com.tr', 'apigateuat.domain.com')
			$rowStr = $rowStr.Replace('apigatedev.domain.com', 'apigateuat.domain.com')
			$rowStr = $rowStr.Replace('close', 'apigateuat.domain.com')
            $rowStr = $rowStr.Replace('127.0.0.1', 'apigateuat.domain.com')
            if ( $rowStr -like 'client-ip*' ) {
                "client-ip: " + $clientip | Out-File -FilePath  $reqFile  -Append -Encoding ASCII
            }
			#elseif( $rowStr -like 'apikey*' )
            #{
            #	"apikey: "+$apikey | Out-File -FilePath  $reqFile  -Append -Encoding ASCII
            #}
            #elseif( $rowStr -like 'keysecret*' )
            #{
            #	"keysecret: "+$keysecret | Out-File -FilePath  $reqFile  -Append -Encoding ASCII
            #}
            elseif ( $rowStr -like 'content-type:*' -and $rowStr -like '*json*' ) {
                "content-type: application/json;charset=utf-8" | Out-File -FilePath  $reqFile -Append -Encoding ASCII
            }
            elseif ( $rowStr -like 'content-type:*' -and $rowStr -like '*xml*' ) {
                "content-type: text/xml;charset=utf-8" | Out-File -FilePath  $reqFile -Append -Encoding ASCII
            }  
           # elseif ( $rowStr -like 'host:*' -and $rowStr -like '*domain.com*' ) {
            #    "host: apigateuat.domain.com" | Out-File -FilePath  $reqFile -Append -Encoding ASCII
            #}     
            #elseif ( $rowStr -like 'authorization*' -and $rowStr -like '*basic*' ) {
            #    "Authorization: Basic " + $token | Out-File -FilePath  $reqFile -Append -Encoding ASCII
            #}
			elseif ( $rowStr -like 'content-length*') {
				Out-File -FilePath  $reqFile -Append -Encoding ASCII
            }
            elseif ( $rowStr -like 'accept*') {
				Out-File -FilePath  $reqFile -Append -Encoding ASCII
            }
            elseif ( $rowStr -like 'sing*') {
				Out-File -FilePath  $reqFile -Append -Encoding ASCII
            }
            elseif ( $rowStr -like 'x-api*') {
				Out-File -FilePath  $reqFile -Append -Encoding ASCII
            }
            else {
                $rowStr | Out-File -FilePath  $reqFile -Append -Encoding ASCII
                #Out-File -FilePath  $reqFile -Append -Encoding ASCII
            }
        }

        write-output "" | Out-File -FilePath  $reqFile -Append -Encoding ASCII
        $contentArr = $CharArray | select -skip 2
        $contentStr = $contentArr -join " "
        $contentStr | Out-File -FilePath $reqFile -Append -Encoding ASCII
    }

    if ($row['RESP']) {
        $CharArray = $row['RESP'].Split([Environment]::NewLine, [System.StringSplitOptions]::RemoveEmptyEntries)

        $CharArray[0].Replace("ResponseHttpStatus: 200", "HTTP/1.1 200 OK").Trim() | Out-File -FilePath $respFile  -Encoding ASCII
        $autWord = $CharArray[1].Replace('headers: ', '')
	
        foreach ($row IN $autWord) {
            $row.Trim() | Out-File -FilePath  $respFile -Append -Encoding ASCII
        }	

        write-output "" | Out-File -FilePath   $respFile -Append -Encoding ASCII
        $contentArr = $CharArray | select -skip 2
        $contentStr = $contentArr -join " "
        $contentStr | Out-File -FilePath $respFile -Append -Encoding ASCII
    }
}
If (Test-Path -Path "C:\saz\raw.zip") {
    Remove-Item "C:\saz\raw.zip"   -Recurse

    # Alias for 7-zip
    if (-not (test-path "$env:ProgramFiles\7-Zip\7z.exe")) { throw "$env:ProgramFiles\7-Zip\7z.exe needed" }
    Set-Alias sz "$env:ProgramFiles\7-Zip\7z.exe"
 
    $source = "C:\saz\raw"
    $target = "C:\saz\raw.zip"

    sz  a -mx=9 $target $source
}
Else {
    # Alias for 7-zip
    if (-not (test-path "$env:ProgramFiles\7-Zip\7z.exe")) { throw "$env:ProgramFiles\7-Zip\7z.exe needed" }
    Set-Alias sz "$env:ProgramFiles\7-Zip\7z.exe"
 
    $source = "C:\saz\raw"
    $target = "C:\saz\raw.zip"

    sz  a -mx=9 $target $source
}
If (Test-Path -Path "C:\saz\raw.saz") {
    Remove-Item "C:\saz\raw.saz"   -Recurse
    Rename-Item -Path  "C:\saz\raw.zip" -NewName  "C:\saz\raw.saz"
}
Else {
    Rename-Item -Path  "C:\saz\raw.zip" -NewName  "C:\saz\raw.saz"
}