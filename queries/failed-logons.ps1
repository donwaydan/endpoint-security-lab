# Detect repeated failed logons (Windows Security event 4625) in the last 24 hours.
# Groups by account, logon type and source IP; flags 3 or more failures.
$since = (Get-Date).AddHours(-24)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$since} -ErrorAction SilentlyContinue |
  ForEach-Object {
    [pscustomobject]@{
      Time      = $_.TimeCreated
      Account   = $_.Properties[5].Value
      LogonType = $_.Properties[10].Value
      Status    = '0x{0:X}' -f $_.Properties[7].Value
      SubStatus = '0x{0:X}' -f $_.Properties[9].Value
      SourceIP  = $_.Properties[19].Value
    }
  } |
  Group-Object Account, LogonType, SourceIP |
  Where-Object Count -ge 3 |
  Select-Object Count, Name |
  Sort-Object Count -Descending
