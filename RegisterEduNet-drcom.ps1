param (
    [Parameter(Mandatory = $false)]
    [string]$username = "",
    [Parameter(Mandatory = $false)]
    [string]$b64pass = "",
    [switch]$dry_run
)
$clearpass = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($b64pass))

$baseUri = "http://172.30.255.42:801"
$path = "/eportal/portal/login"
$param = "?callback=dr1003&login_method=1&user_account=%2C0%2C$username&user_password=$clearpass&wlan_user_ip=&wlan_user_ipv6=&wlan_user_mac=000000000000&wlan_ac_ip=&wlan_ac_name=&jsVersion=4.1.3&terminal_type=1&lang=zh-cn&v=3685&lang=zh"

if ($dry_run) {
    Write-Output "Uri request: $baseUri$path$param"
}
else {
    Invoke-WebRequest -Method Get -Uri $baseUri$path$param
}
