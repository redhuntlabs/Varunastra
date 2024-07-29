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
./varunastra <docker-image>
```


#### Example 

```bash
./varunastra trufflesecurity/secrets
```

```
2024/06/21 18:57:24 Regex File refresh not required. The latest file is within the 1-hour threshold.
2024/06/21 18:57:24 regexes.json
2024/06/21 18:57:24 Starting Scan for Image: trufflesecurity/secrets
2024/06/21 18:57:27 Processing layer with digest: sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59
2024/06/21 18:57:27
2024/06/21 18:57:27 Secrets found -> Type: AWS Secret Access Key | Secret: aws_secret_access_key = Tg0pz8Jii8hkLx4+PnUisM8GmKs3a2DK+9qz/lie | On Path: aws
2024/06/21 18:57:27
2024/06/21 18:57:27 Secrets found -> Type: AWS Access Key | Secret: AKIAXYZDQCEN4B6JSJQI | On Path: aws
2024/06/21 18:57:27 Processing history entries
2024/06/21 18:57:27 Successfully removed Docker image: trufflesecurity/secrets
2024/06/21 18:57:27 Scanning completed.
{
  "target": "trufflesecurity/secrets",
  "data": [
    {
      "issue": "Secret Leaked in Docker Container",
      "asset": "aws",
      "title": "AWS Secret Access Key",
      "variant_description": "aws_secret_access_key = Tg0pz8Jii8hkLx4+PnUisM8GmKs3a2DK+9qz/lie",
      "layer_digest": "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59"
    },
    {
      "issue": "Secret Leaked in Docker Container",
      "asset": "aws",
      "title": "AWS Access Key",
      "variant_description": "AKIAXYZDQCEN4B6JSJQI",
      "layer_digest": "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59"
    }
  ],
  "Version": "1.0"
}
```