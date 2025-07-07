if ($null -eq (Get-Module ImportExcel)) { Import-Module ImportExcel -ErrorAction Stop }


# +--------------------------+
# | ==> GLOBAL VARIABLES <== |
# +--------------------------+

[String]$GLOBAL:OUT_DIR = 'Ripped'
[String]$GLOBAL:CIS_OUT_DIR = "$GLOBAL:OUT_DIR\CIS"
[String]$GLOBAL:RULDP_OUT_DIR = "$GLOBAL:OUT_DIR\Rule-Deployer"
[String]$GLOBAL:FILTERED_FILEPATH = "$GLOBAL:OUT_DIR\FilteredRules.txt"
[String]$GLOBAL:POLICIES_NSX_PATH = 'infra/domains/default/gateway-policies'
[String]$GLOBAL:SECGROUP_NSX_PATH = 'infra/domains/default/groups'
[String]$GLOBAL:SERVICES_NSX_PATH = 'infra/services'

[System.Drawing.Color]$GLOBAL:EXCEL_FILLTHIS_BG_COLOR = [System.Drawing.ColorTranslator]::FromHtml("#FCC060")
[System.Drawing.Color]$GLOBAL:EXCEL_HEADER_BG_COLOR = [System.Drawing.Color]::Yellow
[String]$GLOBAL:RULDP_WS_SGRPS = 'TSA-SecurityGroups'
[String]$GLOBAL:RULDP_WS_SRVCS = 'TSA-Services'
[String]$GLOBAL:RULDP_WS_RULES = 'TSA-Rules'

[String]$U8_REGEX = '([0-1]?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))'
[String]$NAT_REGEX = '([1-9]|[1-2][0-9]|3[0-2])'
[Regex]$GLOBAL:IP_REGEX = "^(($U8_REGEX\.){3}($U8_REGEX))(/($NAT_REGEX))?$"
[Regex]$GLOBAL:SERVICE_NAME_REGEX = "^t\d{3}_svc-(.+)$"
[Regex]$GLOBAL:SECGROUP_NAME_REGEX = "^t\d{3}_grp-(vm|nsm|nest|ips)-(.+)$"
[Regex]$GLOBAL:RULE_NAME_REGEX = '^(t\d{3})_pfw(pay|inet)-([A-Z]{3,6}\d{5,8})[_-]+((\d+)[_-]+)?(.*)$'
# RULE_NAME Matches : 1 -> Tenant; 2 -> Gateway; 3 -> Request-ID; 5 -> Index; 6 -> Description

[String[]]$GLOBAL:EXCLUDE_MATCHES = @("UAN")
[PSCustomObject[]]$GLOBAL:ANY_DESTINATION = @([PSCustomObject]@{ ipv4 = "ANY" })
[PSCustomObject[]]$GLOBAL:ANY_SOURCE = @([PSCustomObject]@{ ipv4 = "ANY" })
[PSCustomObject[]]$GLOBAL:ANY_SERVICE = @(
    [PSCustomObject]@{ protocol = "TCP";  port = "1-65535" }
    [PSCustomObject]@{ protocol = "UDP";  port = "1-65535" }
    [PSCustomObject]@{ protocol = "ICMP"; port = "8"       }
)

[PSCustomObject]$GLOBAL:ANY_DESTINATION_DATA = [PSCustomObject]@{ abstract = "Any"; resolved = $GLOBAL:ANY_DESTINATION }
[PSCustomObject]$GLOBAL:ANY_SOURCE_DATA = [PSCustomObject]@{ abstract = "Any"; resolved = $GLOBAL:ANY_SOURCE }
[PSCustomObject]$GLOBAL:ANY_SERVICE_DATA = [PSCustomObject]@{ svc_name = "Any"; resolved = $GLOBAL:ANY_SERVICE }


# +---------------+
# | ==> UTILS <== |
# +---------------+

# Format a word as singular or plural depending on cardinality
function Pl {
    param ([Int]$cardinality, [String]$singular = "", [String]$plural = "s")
    if ($cardinality -eq 1) { return $singular } else { return $plural }
}

# Print out a line of dialogue; calling again overwrites the same line
function LogInPlace {
    param ([String]$message)
    Write-Host -NoNewline "`r$message"
    Write-Host -NoNewline (" " * ([System.Console]::BufferWidth - $message.Length))
}

# Use LogInPlace-logic but end with a newline
function LogLine {
    param ([String]$message)
    LogInPlace $message; Write-Host $null
}


# Checks if `str` matches any of the `match_attempts`
function  MatchesAny {
    param ([String]$str, [String[]]$match_attempts)
    return $null -ne ($match_attempts | Where-Object { $str -match $_ })
}

# Get the first non-null element of a given array
function FirstNonNull {
    param ([Array]$arr)
    return $arr | Where-Object { $null -ne $_ } | Select-Object -First 1
}


# +---------------+
# | ==> TYPES <== |
# +---------------+

class NsxApiHandle {
    [String]$base_url
    [Hashtable]$headers
    [Hashtable]$cache = @{}
    [Int]$timeout_sec = 5

    NsxApiHandle ([String]$base_url) {
        if (-not $base_url)         { throw "NSX Host Domain was not provided" }
        if (-not $env:nsx_user)     { throw "NSX Username was not provided" }
        if (-not $env:nsx_password) { throw "NSX Password was not provided" }
        [Byte[]]$bytes = [System.Text.Encoding]::UTF8.GetBytes("${env:nsx_user}:${env:nsx_password}")
        [String]$encoded = [Convert]::ToBase64String($bytes) 
        $this.base_url = $base_url
        $this.headers = @{
            Authorization = "Basic $encoded"
        }
    }

    # Make GET Request to the NSX API
    [PSCustomObject] ApiGet ([String]$path) {
        if ($null -eq $this.cache[$path]) {
            [String]$url = "$($this.base_url)/api/v1/$path"
            $this.cache[$path] = Invoke-RestMethod -Method Get -Uri $url -Headers $this.headers -TimeoutSec $this.timeout_sec
        }; return $this.cache[$path]
    }

    # Get policies from the NSX API
    [String[]] AllPolicies () {
        return $this.ApiGet($GLOBAL:POLICIES_NSX_PATH).results `
        | ForEach-Object { $_.id }
    }

    # Get all Rules of a given policy from the NSX API
    [PSCustomObject[]] AllRulesInPolicy ([String]$policy_id) {
        return $this.ApiGet("$GLOBAL:POLICIES_NSX_PATH/$policy_id/rules").results
    }

    # Get a list of IP-Addresses for a Security Group Path
    [String[]]RipSecurityGroupAddrs ([String]$secgroup_path) {
        if ($secgroup_path -match $GLOBAL:IP_REGEX) { return @($secgroup_path) }
        return $this.ApiGet($secgroup_path).expression | ForEach-Object {
            if ($_.paths) { $_.paths | ForEach-Object { $this.RipSecurityGroupAddrs($_.Trim("/")) } }
            else { $_.ip_addresses }
        }
    }

    # Format a given Security Group for CIS
    [PSCustomObject]RipSecurityGroup ([String]$secgroup_path) {
        [String]$grp_name = if ($secgroup_path -match $GLOBAL:IP_REGEX) { $null }
        else { $this.ApiGet($secgroup_path).display_name }
        if ($grp_name -match $GLOBAL:SECGROUP_NAME_REGEX) { $grp_name = $Matches[2]; switch ($Matches[1]) {
            ("vm")   { $grp_name += " (VM)"      }
            ("nsm")  { $grp_name += " (SEGMENT)" }
            ("nest") { $grp_name += " (GROUP)"   }
        } }
        [PSCustomObject[]]$addrs = $this.RipSecurityGroupAddrs($secgroup_path) | ForEach-Object { [PSCustomObject]@{ ipv4 = $_ } }
        [String]$abstract = if ($grp_name) { $grp_name } else { ($addrs | ForEach-Object { $_.ipv4 }) -join "`r`n" }
        return [PSCustomObject]@{ resolved = @($addrs); grp_name = $grp_name; abstract = $abstract }
    }

    # Format a given Source Group for CIS
    [PSCustomObject]RipSourceGroup ([String]$secgroup_path) {
        if ($secgroup_path -eq "ANY") { return $GLOBAL:ANY_SOURCE_DATA }
        return $this.RipSecurityGroup($secgroup_path)
    }

    # Format a given Destination Group for CIS
    [PSCustomObject]RipDestinationGroup ([String]$secgroup_path) {
        if ($secgroup_path -eq "ANY") { return $GLOBAL:ANY_DESTINATION_DATA }
        return $this.RipSecurityGroup($secgroup_path)
    }

    # Get a list of Protocol-Port Pairs for a Service Path
    [PSCustomObject[]]RipServicePorts ([String]$service_path) {
        return @($this.ApiGet($service_path).service_entries | ForEach-Object {
            if ($_.nested_service_path) { $this.RipServicePorts($_.nested_service_path.Trim("/")) }
            else {
                [String]$protocol = if ($_.alg -eq "FTP") { "TCP" } else { FirstNonNull @($_.l4_protocol, $_.protocol) }
                [String[]]$ports = if ($protocol -match "ICMP") { FirstNonNull @($_.icmp_type, "8") } else { $_.destination_ports }
                $ports | ForEach-Object { [PSCustomObject]@{ port = $_; protocol = $protocol } }
            }
        })
    }

    # Format a given Service for CIS
    [PSCustomObject]RipService ([String]$service_path) {
        if ($service_path -eq "ANY") { return $GLOBAL:ANY_SERVICE_DATA }
        [String]$svc_name = $this.ApiGet($service_path).display_name
        if ($svc_name -match $GLOBAL:SERVICE_NAME_REGEX) { $svc_name = $Matches[1] }
        [PSCustomObject[]]$ports = $this.RipServicePorts($service_path)
        return [PSCustomObject]@{ resolved = @($ports); svc_name = $svc_name }
    }

    # Format Security Groups + Services of a given Rule for CIS
    [PSCustomObject] DeepRip ([PSCustomObject]$rule) {
        return [PSCustomObject]@{
            services     = @($rule.services           | ForEach-Object { $this.RipService($_.Trim("/")) })
            sources      = @($rule.source_groups      | ForEach-Object { $this.RipSourceGroup($_.Trim("/")) })
            destinations = @($rule.destination_groups | ForEach-Object { $this.RipDestinationGroup($_.Trim("/")) })
        }
    }
}


# +------------------------------+
# | ==> MAIN EXECUTION LOGIC <== |
# +------------------------------+

# Load Environment Variables
Get-Content -Path "$PSScriptRoot\.env" | ForEach-Object {
    if ($_ -match '^\s*(#.*)?$') { return }
    [String[]]$parts = $_ -split '=', 2
    if ($parts.Count -eq 2) {
        $name = $parts[0].Trim()
        $value = $parts[1].Trim()
        [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
}

try {
# Fetch all Rules and filter by specified Format
LogInPlace "Fetching policies from NSX"
[String[]]$unused_log = @()
[NsxApiHandle]$handle = [NsxApiHandle]::New($env:nsx_host)
[PSCustomObject[]]$policies = $handle.AllPolicies()
[PSCustomObject[]]$rules = $policies | ForEach-Object {
    [String]$policy = $_
    LogInPlace "Fetching rules from policy : $policy"
    $handle.AllRulesInPolicy($policy)
} | ForEach-Object {
    if (MatchesAny $_.display_name $GLOBAL:EXCLUDE_MATCHES) {
        $unused_log += $_.display_name
    } elseif ($_.display_name -match $GLOBAL:RULE_NAME_REGEX) {
        [PSCustomObject]@{
            rule = $_
            name = $Matches[0]
            tenant = $Matches[1]
            gateway = $Matches[2]
            request = $Matches[3]
            index = [Int]$Matches[5]
            description = $Matches[6]
        }
    } else { $unused_log += $_.display_name }
};  New-Item -ItemType Directory -Force $GLOBAL:OUT_DIR | Out-Null
($unused_log | Sort-Object | Select-Object -Unique) -join "`r`n" `
| Out-File -FilePath $GLOBAL:FILTERED_FILEPATH -Encoding UTF8
$n = $rules.Count; LogLine "Collected $n rule$(Pl $n), filtered out $($unused_log.Count)"

# Group Rules by respective Request ID
[Hashtable]$request_map = @{}
foreach ($rule_data in $rules) {
    LogInPlace "Grouping rules by request : $($rule_data.rule.display_name)"
    [String]$req = $rule_data.request
    if ($request_map[$req]) { $request_map[$req] += $rule_data }
    else { $request_map[$req] = @($rule_data) }
};  $n = $request_map.Keys.Count; LogLine "Created $n request group$(Pl $n)"

# Deep-Rip Request ID Groups
# Create a Second Collection by Tenant
[Hashtable]$tenant_map = @{}
[PSCustomObject[]]$request_groups = @()
foreach ($request in $request_map.Keys | Sort-Object) {
    [Int]$new_index = 1
    [String[]]$tenants = @()
    [PSCustomObject[]]$ripped_rules = @()
    foreach ($rule_data in $request_map[$request] | Sort-Object -Property index) {
        LogInPlace "Deep-ripping rules for $request : $($rule_data.rule.display_name)"
        [String]$tenant = $rule_data.tenant
        [PSCustomObject]$deep_ripped = $handle.DeepRip($rule_data.rule)
        [PSCustomObject]$rule = [PSCustomObject]@{
            tenant = $tenant
            entry_index = $new_index
            gateway = $rule_data.gateway
            description = $rule_data.description
            sources = @($deep_ripped.sources)
            services  = @($deep_ripped.services)
            destinations = @($deep_ripped.destinations)
            request = $request
        }
        if ($tenant -notin $tenants) { $tenants += $tenant }
        if ($tenant_map[$tenant]) { $tenant_map[$tenant] += $rule }
        else { $tenant_map[$tenant] = @($rule) }
        $ripped_rules += $rule
        $new_index += 1
    }; $request_groups += [PSCustomObject]@{
        rules = $ripped_rules
        request = $request
        tenants = $tenants
    }
};  $n = $tenant_map.Keys.Count; LogLine "Created $n tenant collection$(Pl $n)"

# Save each Tenant Collection as a Rule-Deployer Excel File
[Int]$number_of_generated_excel_files = 0
New-Item -Force -ItemType Directory -Path $GLOBAL:RULDP_OUT_DIR | Out-Null
foreach ($tenant in $tenant_map.Keys) {
    [String]$t_out_path = "$GLOBAL:RULDP_OUT_DIR/FW-Rules-$tenant.xlsx"
    [PSCustomObject[]]$collection = $tenant_map[$tenant]
    if ($collection.Count -eq 0) { continue }
    LogInPlace "Saving : $t_out_path"
    $collection | ForEach-Object {
        [String]$check_inet = if ($_.gateway -eq "inet") { "X" }
        [String]$check_pay  = if ($_.gateway -eq "pay")  { "X" }
        [PSCustomObject]@{
            'Index' = $_.entry_index
            'NSX-Source' = @($_.sources | ForEach-Object { $_.abstract }) -join "`r`n"
            'NSX-Destination' = @($_.destinations | ForEach-Object { $_.abstract }) -join "`r`n"
            'NSX-Service' = @($_.services | ForEach-Object { $_.svc_name }) -join "`r`n"
            'NSX-Description' = $_.description
            'Request ID' = $_.request
            'CIS ID' = $null
            'T0 Internet' = $check_inet
            'T1 Payload'  = $check_pay
            'Creation Status' = $null
        }
    } | Export-Excel -Path $t_out_path -WorksheetName $GLOBAL:RULDP_WS_RULES -CellStyleSB {
        param ($worksheet)
        [Int]$cols = 10
        [Int]$lr = $collection.Count + 1
        [String]$lc = [Char]([Int][Char]'A' + $cols - 1)
        $h_range = $worksheet.Cells["A1:${lc}1"]
        $i_range = $worksheet.Cells["A2:A${lr}"]
        $w_range = $worksheet.Cells["B2:D${lr}"]
        $gw_range = $worksheet.Cells["H2:I${lr}"]
        $cid_range = $worksheet.Cells["G2:G${lr}"]
        $a_range = $worksheet.Cells["A1:${lc}${lr}"]

        $a_range.Style.VerticalAlignment = 'Top'
        $h_range.Style.HorizontalAlignment = 'Center'
        $i_range.Style.HorizontalAlignment = 'Center'
        $cid_range.Style.HorizontalAlignment = 'Center'
        $gw_range.Style.HorizontalAlignment = 'Center'
        $gw_range.Style.VerticalAlignment = 'Center'

        $h_range.Style.Font.Bold = $true
        $h_range.Style.Fill.PatternType = 'Solid'
        $h_range.Style.Fill.BackgroundColor.SetColor($GLOBAL:EXCEL_HEADER_BG_COLOR)

        $cf = $cid_range.ConditionalFormatting.AddExpression()
        $cf.Formula = 'ISBLANK(G2)'
        $cf.Style.Fill.PatternType = 'Solid'
        $cf.Style.Fill.BackgroundColor.Color = $GLOBAL:EXCEL_FILLTHIS_BG_COLOR
    
        $w_range.Style.WrapText = $false
        $worksheet.Cells.AutoFitColumns()
        $worksheet.Column(7).Width = 12
        $w_range.Style.WrapText = $true
    }
    $number_of_generated_excel_files += 1
};  $n = $number_of_generated_excel_files; LogLine "Generated $n Rule-Deployer Excel file$(Pl $n)"

# Build Naive Tenant Groups
[Hashtable]$naive_groups = @{}
foreach ($r in $request_groups) {
    [String]$k = $r.tenants -join "_"
    if ($naive_groups[$k]) { $naive_groups[$k] += $r }
    else { $naive_groups[$k] = @($r) }
}

# Build Tenant Graph
[Hashtable]$tenant_graph = @{}
foreach ($g in $naive_groups.Values) {
    foreach ($t in $g[0].tenants) {
        if (!$tenant_graph[$t]) { $tenant_graph[$t] = @{} }
        foreach ($t1 in $g[0].tenants) { if ($t -ne $t1) { $tenant_graph[$t][$t1] = $true } }
    }
}

# Find Actual Tenant Groups
[Hashtable]$visited = @{}
[String[][]]$tenant_groups = @()
[Hashtable]$tenant_group_map = @{}
function recurse_group_tenant {
    param ([String]$tenant)
    if ($visited[$tenant]) { return $null } else { $visited[$tenant] = $true }
    return @($tenant; ($tenant_graph[$tenant].Keys | ForEach-Object { recurse_group_tenant $_ } | Where-Object { $_ }))
};  foreach ($t in $tenant_graph.Keys) { [String[]]$g = recurse_group_tenant $t | Sort-Object; if ($g.Count) { $tenant_groups += ,$g } }
foreach ($g in $tenant_groups) { [String]$k = $g -join "_"; foreach ($t in $g) { $tenant_group_map[$t] = $k } }

# Build up Final Groups
[Hashtable]$final_groups = @{}
foreach ($tn in $naive_groups.Keys) {
    [String]$k = $tenant_group_map[($naive_groups[$tn][0].tenants[0])]
    if (-not $final_groups[$k]) { $final_groups[$k] = $naive_groups[$tn] }
    else { $final_groups[$k] += $naive_groups[$tn] }
}

# Save all Grouped Rules as individual CIS JSON-Requests
[Int]$number_of_generated_files = 0
foreach ($tenant_s in $final_groups.Keys) {
    [String]$t_out_path = "$GLOBAL:CIS_OUT_DIR\$tenant_s"
    New-Item -Force -ItemType Directory -Path $t_out_path | Out-Null
    foreach ($request_data in $final_groups[$tenant_s]) {
        [String]$request_id = $request_data.request
        [String]$r_out_path = "$t_out_path\$request_id.json"
        LogInPlace "Saving : $r_out_path"

        [String[]]$svc_groups = @()
        [String[]]$sec_groups = @()
        [PSCustomObject[]]$rules = @()
        foreach ($rule in $request_data.rules) {
            $svc_groups += $rule.services | ForEach-Object {
                if ($_.svc_name) { $_.svc_name + " : " + (@($_.resolved | ForEach-Object { $_.protocol + ":" + $_.port }) -join ", ") }
            }
            $sec_groups += @($rule.sources; $rule.destinations) | ForEach-Object {
                if ($_.grp_name) { $_.grp_name + " : " + (@($_.resolved | ForEach-Object { $_.ipv4 }) -join ", ") }
            }
            $rules += [PSCustomObject]@{
                description = $rule.description
                entry_index = $rule.entry_index
                rel_services = @($rule.services | ForEach-Object { $_.resolved })
                rel_src_ipv4s = @($rule.sources | ForEach-Object { $_.resolved })
                rel_dst_ipv4s = @($rule.destinations | ForEach-Object { $_.resolved })
            }
        }

        $svc_groups = $svc_groups | Select-Object -Unique | Where-Object { $_ } | ForEach-Object { "- $_"}
        $sec_groups = $sec_groups | Select-Object -Unique | Where-Object { $_ } | ForEach-Object { "- $_"}
        [String]$comment = "Tenants: $(($request_data.tenants | Sort-Object) -join ", ")"
        if ($svc_groups.Count) { $comment += "`n`nServices:`n" + ($svc_groups -join "`n") }
        if ($sec_groups.Count) { $comment += "`n`nSecurity Groups:`n" + ($sec_groups -join "`n") }

        [PSCustomObject]@{
            req_desc = $request_id
            fw_cust_rules_ipv6 = @()
            fw_cust_rules_ipv4 = @($rules)
            req_comment = $comment
        } | ConvertTo-Json -Depth 8 -Compress `
          | Out-File -FilePath $r_out_path -Encoding UTF8
        $number_of_generated_files += 1
    }
}; $n = $number_of_generated_files; LogLine "Generated $n CIS-json file$(Pl $n)"
LogLine "Done!"
} catch { $Host.UI.WriteErrorLine($_.Exception.Message); exit 1 }

# - [x] Convert ANY (Service)
#       --------------
#       TCP  : 1-65535
#       UDP  : 1-65535
#       ICMP : 8
# - [x] Handle dubious Service Formats
#     - [x] FTP -> Map to TCP
#     - [x] nested
#     - [x] ICMP -> use icmp_type in the protocol field
#         - [x] ICMPv4-ALL
#         - [x] ICMPv6-ALL
#         - [x] ICMP_Echo_Request
#         - [x] ICMP_Echo_Response
#         - [x] IPv6-ICMP_Echo_Request
#         - [x] IPv6-ICMP_Echo_Response
# - [x] Convert ANY (Source) -> ANY
# - [x] Convert ANY (Destination) -> ANY
# - [x] req_comment: 'Tenants: t0XX'
# - [x] UAN in name -> filter away
# - [x] Sort by enty index *numerically*
# - [x] req_comment: Add unresolved Security and Service Groups
# - [x] Build up ruledeployer style Excel Sheets (one per tenant!)
# - [ ] How are we gonna resolve literal IPs? New Groups?

# IMPORTANT: Change to literal "ANY" for security groups
#            Service Group in descritpion
#            FTP!!! (use service object!!)

# IDC<cis_id>_<ind(1,)>
