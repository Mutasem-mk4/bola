# Automated QA Integration Test for Bola
$ErrorActionPreference = "Stop"

# Ignore SSL errors and force TLS 1.2 in older PowerShell
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "[*] Starting Proxy Engine on Port 8888..." -ForegroundColor Cyan
$proxyJob = Start-Process -FilePath "C:\Users\User\go\bin\bola.exe" -ArgumentList "proxy", "-c", "bola.yaml" -RedirectStandardOutput "proxy.log" -RedirectStandardError "proxy_err.log" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3

# Identity Cookies
$ownerCookie = "intercom-id-boaw5c39=eda907e9-4f0c-4455-8485-d3c71d95a647; intercom-session-boaw5c39=; intercom-device-id-boaw5c39=87124da5-3551-4acb-9124-c688f1e909b9; htjs_anonymous_id=d655d69a-8fe4-435f-bb96-627e49b1941c; _csrf_token=b708708d49e7c05c80b0cf5fb99dc9effc2b1a492cb6dad6491989e4fc5f67d8.R5YyALNo62EqMFKPqhhVnmUZQtY; htjs_user_id=magic-developer:0tJ7-kQROoDbA3as9GiNHc_5yFP2Rt8sfhrVwq6y0Wo=; htjs_sesh={%22id%22:1776704047646%2C%22expiresAt%22:1776707917350%2C%22timeout%22:1800000%2C%22sessionStart%22:false%2C%22autoTrack%22:true}; _dd_s=logs=1&id=48268346-85e5-48c7-8fbb-92b3786d8a73&created=1776706073284&expire=1776707276002&rum=0"
$attackerCookie = "_ga=GA1.1.149399366.1776702818; _twpid=tw.1776702825254.857884513857417511; intercom-id-boaw5c39=73de1858-ac45-4b6e-8403-a776fa0aa4eb; intercom-session-boaw5c39=; intercom-device-id-boaw5c39=718822fc-e790-4915-856d-61e3c4c4863e; _ga_992J013BXQ=GS2.1.s1776702821`$o1`$g0`$t1776702891`$j60`$10`$h0; htjs_anonymous_id=6fc710fd-6037-4a2d-834f-13f7319b31ac; _gcl_au=1.1.2061386156.1776702818.1904419734.1776702892.1776703744; _csrf_token=47b4ee24b7feeb4f7fdbcd16aa629a0cb42c3decbc6e07887e93993aca3a00a7.WLrWR7oNPdJOxgxn9YzQeymczQY; htjs_user_id=magic-developer:5tWe0MEoX_GY4Kgoi33NSykddzBiV9JDDKs8b01K7Mk=; __stripe_mid=1f984d99-3112-4e1f-97e3-9cb61cec267223934e; htjs_sesh={%22id%22:1776706646892%2C%22expiresAt%22:1776708449056%2C%22timeout%22:1800000%2C%22sessionStart%22:false%2C%22autoTrack%22:true}; _ga_G4TN253S40=GS2.1.s1776706650`$o2`$g0`$t1776706650`$j60`$10`$h0; __stripe_sid=5a56b69b-037a-4a8a-bc71-9771e8a1593e213596; _dd_s=logs=1&id=913a2f91-6ebf-44a2-8620-e2ff889e33a03&created=1776706645959&expire=1776707614462&rum=0"

$proxyUrl = "http://127.0.0.1:8888"

Write-Host "[*] Executing test 1 (Owner)..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "https://api.dashboard.magic.link/v1/magic_client/r85h34hQg16SegSbk_3I5zh4r7ZIvfl9hwSU5KvMToE=/users" -Proxy $proxyUrl -Headers @{ "Cookie" = $ownerCookie } -Method Get | Out-Null
    Write-Host " [Success]" -ForegroundColor Green
} catch {
    Write-Host " [Failed] $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "[*] Executing test 2 (Attacker)..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "https://api.dashboard.magic.link/v1/magic_client/attacker_client_id/users" -Proxy $proxyUrl -Headers @{ "Cookie" = $attackerCookie } -Method Get | Out-Null
    Write-Host " [Success]" -ForegroundColor Green
} catch {
    Write-Host " [Failed] $($_.Exception.Message)" -ForegroundColor Red
}

Start-Sleep -Seconds 2
Write-Host "[*] Stopping Proxy Engine..." -ForegroundColor Cyan
Stop-Process -Id $proxyJob.Id -Force -ErrorAction SilentlyContinue

Write-Host "[*] Running BOLA Scanner..." -ForegroundColor Green
& "C:\Users\User\go\bin\bola.exe" scan -c bola.yaml

Write-Host "[*] QA Test Complete." -ForegroundColor White
