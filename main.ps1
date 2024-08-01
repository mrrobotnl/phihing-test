# Functie om een .eml-bestand in te lezen en te analyseren
function Analyze-PhishingEmail {
    param (
        [string]$emlFilePath
    )

    # Controleer of het bestand bestaat
    if (-Not (Test-Path -Path $emlFilePath)) {
        Write-Host "Bestand niet gevonden: $emlFilePath"
        return
    }

    # Lees de inhoud van het .eml-bestand
    $emlContent = Get-Content -Path $emlFilePath -Raw

    # Maak een map voor de resultaten
    $resultsPath = "$($emlFilePath)_results"
    if (-Not (Test-Path -Path $resultsPath)) {
        New-Item -ItemType Directory -Path $resultsPath
    }

    # Analyseer afzenderinformatie
    if ($emlContent -match "From:.*?<(.+?)>") {
        $senderEmail = $matches[1]
        Write-Host "Afzender e-mail: $senderEmail"
        Add-Content -Path "$resultsPath\sender_email.txt" -Value $senderEmail
    }

    # Zoek naar URLs in de e-mailinhoud
    $urls = Select-String -Pattern "https?://[^\s]+" -InputObject $emlContent -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
    if ($urls) {
        Write-Host "Gevonden URLs:"
        $urls | ForEach-Object { Write-Host $_; Add-Content -Path "$resultsPath\urls.txt" -Value $_ }
    }

    # Zoek naar IP-adressen in de e-mailinhoud
    $ips = Select-String -Pattern "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b" -InputObject $emlContent -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
    if ($ips) {
        Write-Host "Gevonden IP-adressen:"
        $ips | ForEach-Object { Write-Host $_; Add-Content -Path "$resultsPath\ips.txt" -Value $_ }
    }

    # Zoek naar Base64-strings in de e-mailinhoud
    $base64Strings = Select-String -Pattern "(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?" -InputObject $emlContent -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
    if ($base64Strings) {
        Write-Host "Gevonden Base64-strings:"
        $base64Strings | ForEach-Object { Write-Host $_; Add-Content -Path "$resultsPath\base64_strings.txt" -Value $_ }
    }

    # Controleer elke URL op phishing-indicatoren
    foreach ($url in $urls) {
        # Basis check op verdachte woorden in de URL
        if ($url -match "login|secure|account|update|verify|password") {
            Write-Host "Waarschuwing: Mogelijke phishing-URL gedetecteerd: $url"
            Add-Content -Path "$resultsPath\phishing_warnings.txt" -Value "Mogelijke phishing-URL: $url"
        }

        # Maak een webrequest naar de URL om de HTTP-status te controleren
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Method Head -TimeoutSec 10
            Write-Host "URL Response Status Code: $($response.StatusCode) - $url"
            Add-Content -Path "$resultsPath\url_responses.txt" -Value "URL: $url - Status Code: $($response.StatusCode)"
        } catch {
            Write-Host "Waarschuwing: Kan geen verbinding maken met URL: $url"
            Add-Content -Path "$resultsPath\url_responses.txt" -Value "Kan geen verbinding maken met URL: $url"
        }
    }
}

# Voer de analyse uit op een opgegeven .eml-bestand
$emlFilePath = "path\to\your\email.eml"
Analyze-PhishingEmail -emlFilePath $emlFilePath
