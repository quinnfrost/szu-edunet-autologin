param (
    [Parameter(Mandatory = $false)]
    [string]$username = "",
    [Parameter(Mandatory = $false)]
    [string]$b64pass = "",
    [string]$dry_run_with_key
)

function Invoke-RegisterRequest {
    param (
        [string]$uri
    )
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("lang", "zh-CN", "/", "net.szu.edu.cn")))
    $response = Invoke-WebRequest -Uri $uri `
        -WebSession $session `
        -Headers @{
        "Accept"             = "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01"
        "Accept-Encoding"    = "gzip, deflate, br, zstd"
        "Accept-Language"    = "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"
        "Cache-Control"      = "no-cache"
        "Pragma"             = "no-cache"
        "Referer"            = "https://net.szu.edu.cn/srun_portal_pc?ac_id=12&theme=proyx"
        "Sec-Fetch-Dest"     = "empty"
        "Sec-Fetch-Mode"     = "cors"
        "Sec-Fetch-Site"     = "same-origin"
        "X-Requested-With"   = "XMLHttpRequest"
        "sec-ch-ua"          = "`"Microsoft Edge`";v=`"131`", `"Chromium`";v=`"131`", `"Not_A Brand`";v=`"24`""
        "sec-ch-ua-mobile"   = "?0"
        "sec-ch-ua-platform" = "`"Windows`""
    }
    if ($response.StatusCode -eq 200) {
        return $response.Content
    }
    else {
        Write-Output $response
        return ""
    }
}

function Get-UnixTimestamp {
    param (
    )
    return [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
}

function Get-HMAC_MD5 {
    param (
        [string]$word,
        [string]$secret
    )
    $hmacsha = New-Object System.Security.Cryptography.HMACMD5
    $hmacsha.key = [Text.Encoding]::ASCII.GetBytes($secret)
    $hash1 = $hmacsha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($word))
  
    return [System.BitConverter]::ToString($hash1).Replace('-', '').ToLower()
}

function Get-SHA1 {
    param (
        [string]$str
    )
    return Get-FileHash -InputStream $([IO.MemoryStream]::new([byte[]][char[]]($str))) -Algorithm SHA1
}

function Get-WSH_JSON_OBJ {
    param (
        [string]$str
    )
    return $str.Replace('"', '%22').Replace("`n", "").Replace("`r", "")
}

function Get-RegisterUri {
    param (
        [Parameter(Mandatory = $true)]
        [string]$key,
        [Parameter(Mandatory = $true)]
        [string]$username,
        [Parameter(Mandatory = $true)]
        [string]$password,
        [Parameter(Mandatory = $true)]
        [string]$ip
    )
    $acid = "12"
    $enc_ver = "srun_bx1"

    # $info = @{
    #   "username"=""
    #   "password"=""
    #   "ip"=""
    #   "acid"="12"
    #   "enc_ver"="srun_bx1"
    # }
    # $escaped_info = Get-WSH_JSON_OBJ $($info |ConvertTo-Json)
    $escaped_info = "{%22username%22:%22$username%22,%22password%22:%22$password%22,%22ip%22:%22$ip%22,%22acid%22:%22$acid%22,%22enc_ver%22:%22$enc_ver%22}"
  

    $hmd5 = Get-HMAC_MD5 -word $password -secret $key
    $hmd5 = $hmd5[-1]
    $encoded_info = $(cscript "$PSScriptRoot/customTEA.js" $escaped_info $key)
    $encoded_info = $encoded_info[-1].ToString()
    $encoded_escaped_info = [uri]::EscapeDataString($encoded_info)
  
    # custom encrypt params
    $n = 200
    $type = 1

    # build up auth payload from Portal.js#sendAuth
    $str = $key + $username
    $str += $key + $hmd5
    $str += $key + $acid
    $str += $key + $ip
    $str += $key + $n
    $str += $key + $type
    $str += $key + $encoded_info
    $chksum = (Get-SHA1 $str).Hash
    $chksum = $chksum.ToLower()

    $timestamp = Get-UnixTimestamp
    $uri = "https://net.szu.edu.cn/cgi-bin/srun_portal?callback=$callback_name&action=login&username=$username&password=%7BMD5%7D$hmd5&os=Windows+10&name=Windows&nas_ip=&double_stack=0&chksum=$chksum&info=$encoded_escaped_info&ac_id=$acid&ip=$ip&n=$n&type=$type&captchaVal=&_=$timestamp"
    return $uri
}

function Get-Ipv4Addr {
    # ipv4 addr of the active interface
    # https://stackoverflow.com/questions/27277701/get-ipv4-address-into-a-variable
    return (
        Get-NetIPConfiguration |
        Where-Object {
            $_.IPv4DefaultGateway -ne $null -and
            $_.NetAdapter.Status -ne "Disconnected"
        }
    ).IPv4Address.IPAddress
}
# Custom base64 and TEA from Portal.js#_encodeUserInfo
$customTEA = @'
//json2 v20160511
"object" != typeof JSON && (JSON = {}),
function() {
    "use strict";
    function f(t) {
        return t < 10 ? "0" + t : t
    }
    function this_value() {
        return this.valueOf()
    }
    function quote(t) {
        return rx_escapable.lastIndex = 0,
        rx_escapable.test(t) ? '"' + t.replace(rx_escapable, function(t) {
            var e = meta[t];
            return "string" == typeof e ? e : "\\u" + ("0000" + t.charCodeAt(0).toString(16)).slice(-4)
        }) + '"' : '"' + t + '"'
    }
    function str(t, e) {
        var r, n, o, u, f, a = gap, i = e[t];
        switch (i && "object" == typeof i && "function" == typeof i.toJSON && (i = i.toJSON(t)),
        "function" == typeof rep && (i = rep.call(e, t, i)),
        typeof i) {
        case "string":
            return quote(i);
        case "number":
            return isFinite(i) ? String(i) : "null";
        case "boolean":
        case "null":
            return String(i);
        case "object":
            if (!i)
                return "null";
            if (gap += indent,
            f = [],
            "[object Array]" === Object.prototype.toString.apply(i)) {
                for (u = i.length,
                r = 0; r < u; r += 1)
                    f[r] = str(r, i) || "null";
                return o = 0 === f.length ? "[]" : gap ? "[\n" + gap + f.join(",\n" + gap) + "\n" + a + "]" : "[" + f.join(",") + "]",
                gap = a,
                o
            }
            if (rep && "object" == typeof rep)
                for (u = rep.length,
                r = 0; r < u; r += 1)
                    "string" == typeof rep[r] && (n = rep[r],
                    o = str(n, i),
                    o && f.push(quote(n) + (gap ? ": " : ":") + o));
            else
                for (n in i)
                    Object.prototype.hasOwnProperty.call(i, n) && (o = str(n, i),
                    o && f.push(quote(n) + (gap ? ": " : ":") + o));
            return o = 0 === f.length ? "{}" : gap ? "{\n" + gap + f.join(",\n" + gap) + "\n" + a + "}" : "{" + f.join(",") + "}",
            gap = a,
            o
        }
    }
    var rx_one = /^[\],:{}\s]*$/
      , rx_two = /\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g
      , rx_three = /"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g
      , rx_four = /(?:^|:|,)(?:\s*\[)+/g
      , rx_escapable = /[\\\"\u0000-\u001f\u007f-\u009f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g
      , rx_dangerous = /[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g;
    "function" != typeof Date.prototype.toJSON && (Date.prototype.toJSON = function() {
        return isFinite(this.valueOf()) ? this.getUTCFullYear() + "-" + f(this.getUTCMonth() + 1) + "-" + f(this.getUTCDate()) + "T" + f(this.getUTCHours()) + ":" + f(this.getUTCMinutes()) + ":" + f(this.getUTCSeconds()) + "Z" : null
    }
    ,
    Boolean.prototype.toJSON = this_value,
    Number.prototype.toJSON = this_value,
    String.prototype.toJSON = this_value);
    var gap, indent, meta, rep;
    "function" != typeof JSON.stringify && (meta = {
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
        '"': '\\"',
        "\\": "\\\\"
    },
    JSON.stringify = function(t, e, r) {
        var n;
        if (gap = "",
        indent = "",
        "number" == typeof r)
            for (n = 0; n < r; n += 1)
                indent += " ";
        else
            "string" == typeof r && (indent = r);
        if (rep = e,
        e && "function" != typeof e && ("object" != typeof e || "number" != typeof e.length))
            throw new Error("JSON.stringify");
        return str("", {
            "": t
        })
    }
    ),
    "function" != typeof JSON.parse && (JSON.parse = function(text, reviver) {
        function walk(t, e) {
            var r, n, o = t[e];
            if (o && "object" == typeof o)
                for (r in o)
                    Object.prototype.hasOwnProperty.call(o, r) && (n = walk(o, r),
                    void 0 !== n ? o[r] = n : delete o[r]);
            return reviver.call(t, e, o)
        }
        var j;
        if (text = String(text),
        rx_dangerous.lastIndex = 0,
        rx_dangerous.test(text) && (text = text.replace(rx_dangerous, function(t) {
            return "\\u" + ("0000" + t.charCodeAt(0).toString(16)).slice(-4)
        })),
        rx_one.test(text.replace(rx_two, "@").replace(rx_three, "]").replace(rx_four, "")))
            return j = eval("(" + text + ")"),
            "function" == typeof reviver ? walk({
                "": j
            }, "") : j;
        throw new SyntaxError("JSON.parse")
    }
    )
}();

jQuery = {}
//jquery-base64 v1.0
"use strict";
jQuery.base64 = (function($) {
    var _PADCHAR = "="
      , _ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
      , _VERSION = "1.0";
    function _getbyte64(s, i) {
        var idx = _ALPHA.indexOf(s.charAt(i));
        if (idx === -1) {
            throw "Cannot decode base64"
        }
        return idx
    }
    function _setAlpha(s) {
        _ALPHA = s;
    }
    function _decode(s) {
        var pads = 0, i, b10, imax = s.length, x = [];
        s = String(s);
        if (imax === 0) {
            return s
        }
        if (imax % 4 !== 0) {
            throw "Cannot decode base64"
        }
        if (s.charAt(imax - 1) === _PADCHAR) {
            pads = 1;
            if (s.charAt(imax - 2) === _PADCHAR) {
                pads = 2
            }
            imax -= 4
        }
        for (i = 0; i < imax; i += 4) {
            b10 = (_getbyte64(s, i) << 18) | (_getbyte64(s, i + 1) << 12) | (_getbyte64(s, i + 2) << 6) | _getbyte64(s, i + 3);
            x.push(String.fromCharCode(b10 >> 16, (b10 >> 8) & 255, b10 & 255))
        }
        switch (pads) {
        case 1:
            b10 = (_getbyte64(s, i) << 18) | (_getbyte64(s, i + 1) << 12) | (_getbyte64(s, i + 2) << 6);
            x.push(String.fromCharCode(b10 >> 16, (b10 >> 8) & 255));
            break;
        case 2:
            b10 = (_getbyte64(s, i) << 18) | (_getbyte64(s, i + 1) << 12);
            x.push(String.fromCharCode(b10 >> 16));
            break
        }
        return x.join("")
    }
    function _getbyte(s, i) {
        var x = s.charCodeAt(i);
        if (x > 255) {
            throw "INVALID_CHARACTER_ERR: DOM Exception 5"
        }
        return x
    }
    function _encode(s) {
        if (arguments.length !== 1) {
            throw "SyntaxError: exactly one argument required"
        }
        s = String(s);
        var i, b10, x = [], imax = s.length - s.length % 3;
        if (s.length === 0) {
            return s
        }
        for (i = 0; i < imax; i += 3) {
            b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) | _getbyte(s, i + 2);
            x.push(_ALPHA.charAt(b10 >> 18));
            x.push(_ALPHA.charAt((b10 >> 12) & 63));
            x.push(_ALPHA.charAt((b10 >> 6) & 63));
            x.push(_ALPHA.charAt(b10 & 63))
        }
        switch (s.length - imax) {
        case 1:
            b10 = _getbyte(s, i) << 16;
            x.push(_ALPHA.charAt(b10 >> 18) + _ALPHA.charAt((b10 >> 12) & 63) + _PADCHAR + _PADCHAR);
            break;
        case 2:
            b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8);
            x.push(_ALPHA.charAt(b10 >> 18) + _ALPHA.charAt((b10 >> 12) & 63) + _ALPHA.charAt((b10 >> 6) & 63) + _PADCHAR);
            break
        }
        return x.join("")
    }
    return {
        decode: _decode,
        encode: _encode,
        setAlpha: _setAlpha,
        VERSION: _VERSION
    }
}(jQuery));
function customTEA(info, token) {
    // 克隆自 $.base64，防止污染
    // var base64 = _this.clone($.base64); // base64 设置 Alpha
    var base64 = jQuery.base64; // base64 设置 Alpha


    base64.setAlpha('LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'); // 用户信息转 JSON

    info = JSON.stringify(info);

    function encode(str, key) {
        if (str === '') return '';
        var v = s(str, true);
        var k = s(key, false);
        if (k.length < 4) k.length = 4;
        var n = v.length - 1,
            z = v[n],
            y = v[0],
            c = 0x86014019 | 0x183639A0,
            m,
            e,
            p,
            q = Math.floor(6 + 52 / (n + 1)),
            d = 0;

        while (0 < q--) {
            d = d + c & (0x8CE0D9BF | 0x731F2640);
            e = d >>> 2 & 3;

            for (p = 0; p < n; p++) {
                y = v[p + 1];
                m = z >>> 5 ^ y << 2;
                m += y >>> 3 ^ z << 4 ^ (d ^ y);
                m += k[p & 3 ^ e] ^ z;
                z = v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF);
            }

            y = v[0];
            m = z >>> 5 ^ y << 2;
            m += y >>> 3 ^ z << 4 ^ (d ^ y);
            m += k[p & 3 ^ e] ^ z;
            z = v[n] = v[n] + m & (0xBB390742 | 0x44C6F8BD);
        }

        return l(v, false);
    }

    function s(a, b) {
        var c = a.length;
        var v = [];

        for (var i = 0; i < c; i += 4) {
            v[i >> 2] = a.charCodeAt(i) | a.charCodeAt(i + 1) << 8 | a.charCodeAt(i + 2) << 16 | a.charCodeAt(i + 3) << 24;
        }

        if (b) v[v.length] = c;
        return v;
    }

    function l(a, b) {
        var d = a.length;
        var c = d - 1 << 2;

        if (b) {
            var m = a[d - 1];
            if (m < c - 3 || m > c) return null;
            c = m;
        }

        for (var i = 0; i < d; i++) {
            a[i] = String.fromCharCode(a[i] & 0xff, a[i] >>> 8 & 0xff, a[i] >>> 16 & 0xff, a[i] >>> 24 & 0xff);
        }

        return b ? a.join('').substring(0, c) : a.join('');
    }

    return '{SRBX1}' + base64.encode(encode(info, token));
}

// ---------- //
function jscript_print(str) {
    WScript.Echo(str)
}

if (WScript.Arguments.length < 2) {
    jscript_print("Not enough args")
    jscript_print("")
    WScript.Quit()
}
info = unescape(WScript.arguments(0))
token = WScript.arguments(1)
jscript_print(info)
jscript_print(token)
try {
    info = JSON.parse(info)
} catch (error) {
    jscript_print(error)
}

jscript_print(customTEA(info, token));

'@
function New-CustomTEA {
    if (-not (Test-Path -Path "$PSScriptRoot/customTEA.js")) {
        Write-Output 'Creating customTEA.js'
        # customTEA.js
        Add-Content -Path "$PSScriptRoot/customTEA.js" -Value $customTEA
    }
}

if (-not $username -or -not $b64pass ) {
    Write-Output "no username or password given"
    Write-Output "Usage: RegisterEduNet -username <string> -b64pass <base64string>"
    Start-Sleep -Seconds 5
    exit 1
}

$clearpass = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($b64pass))
$ip = Get-Ipv4Addr

New-CustomTEA

# $request0 = Invoke-RegisterRequest 'https://net.szu.edu.cn/v2/srun_portal_captcha_image_info?user_name=$username&ip=$ip'
# Write-Output $request0

# proof of work
$timestamp = Get-UnixTimestamp
$callback_name = "jQuery11240010762243080653766_$timestamp"
$uri1 = "https://net.szu.edu.cn/cgi-bin/get_challenge?callback=$callback_name&username=$username&ip=$ip&_=$($timestamp+2)"
if ($dry_run_with_key) {
    Write-Output "Uri request: $uri1"
    $key = $dry_run_with_key
    $servertime = $timestamp
}
else {
    $request1 = Invoke-RegisterRequest -uri $uri1
    $request1 = ([regex]::Matches($request1, '(?<=\()[^)]+(?=\))').Value) | ConvertFrom-Json

    $servertime = $request1.st
    $key = $request1.challenge
}

$uri2 = Get-RegisterUri -key $key -username $username -password $clearpass -ip $ip
if ($dry_run_with_key) {
    Write-Output "Uri request: $uri2"
}
else {
    $request2 = Invoke-RegisterRequest -uri $uri2
    Write-Output $request2
}

Start-Sleep -Seconds 3
exit 0
