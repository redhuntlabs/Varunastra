## Varunastra: Securing the Depths of Docker

Introducing Varunastra, an innovative tool designed to enhance the security of Docker environments. Named after The Varunastra (वरुणास्त्र), it is the water weapon according to the Indian scriptures, incepted by Varuna, god of hydrosphere. Varunastra is engineered to detect and help mitigate vulnerabilities in Docker, ensuring robust security across all Docker containers and images.


Objective: Prepare for submission to the BlackHat Tool Arsenal.

Development Roadmap:

Phase 1: Secret Scanner
- Image Scanning: Complete
- Container Scanning: Currently under consideration

Phase 2: Vulnerability Scanner
- Details to be determined

Varunastra aims to fortify Docker systems by detecting hidden secrets and vulnerabilities, ensuring robust security across all containers and images.

### Usage

```bash
❯ varunastra -h
Usage: varunastra --target=STRING [flags]

Flags:
  -h, --help             Show context-sensitive help.
      --target=STRING    Target string
      --scans=STRING     Comma-separated scans (secrets,vuln,assets)
```


#### Example 

```bash
 varunastra --target trufflesecurity/secrets --scans "secrets,vuln,assets"
```

```
2024/10/20 21:32:03 Checking if config file exist
2024/10/20 21:32:03 Starting Scan for Image: trufflesecurity/secrets
2024/10/20 21:32:05 Scanning Layers: sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59
2024/10/20 21:32:05
2024/10/20 21:32:05 Secrets found -> Type: Amazon AWS Access Key ID | Secret: AKIAXYZDQCEN4B6JSJQI | On Path: aws
2024/10/20 21:32:05
2024/10/20 21:32:05 Secrets found -> Type: AWS API Key | Secret: AKIAXYZDQCEN4B6JSJQI | On Path: aws
2024/10/20 21:32:05 Scanning completed.
{
  "target": "trufflesecurity/secrets",
  "secrets": [
    {
      "issue": "Secret Leaked in Docker Layer sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59",
      "asset": "aws",
      "type": "Amazon AWS Access Key ID",
      "secret": "AKIAXYZDQCEN4B6JSJQI"
    },
    {
      "issue": "Secret Leaked in Docker Layer sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59",
      "asset": "aws",
      "type": "AWS API Key",
      "secret": "AKIAXYZDQCEN4B6JSJQI"
    }
  ],
  "vulnerabilities": null
}
```