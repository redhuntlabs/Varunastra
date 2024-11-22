<p align="center">
    <img src="https://devanghacks.in/varunastra/croped_logo.png" alt="varunastra logo" width="200">
  <br>
</p>
<p align="center">
<a href="https://www.gnu.org/licenses/gpl-3.0.en.html/"><img src="https://img.shields.io/badge/license-GPL_3.0-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/Devang-Solanki/Varunastra"><img src="https://goreportcard.com/badge/github.com/Devang-Solanki/Varunastra"></a>
<a href="https://go.dev/blog/go1.22.5"><img src="https://img.shields.io/github/go-mod/go-version/Devang-Solanki/Varunastra"></a>
<a href="https://twitter.com/devangsolankii"><img src="https://img.shields.io/twitter/follow/devangsolankii.svg?logo=twitter"></a>
</p>
<p align="center">
  <a href="#installation-guide-for-varunastra">Installation</a>
  <a href="#usage">Usage</a>
</p>


## Varunastra: Securing the Depths of Docker

Introducing Varunastra, an innovative tool designed to enhance the security of Docker environments. Named after The Varunastra (वरुणास्त्र), it is the water weapon according to the Indian scriptures, incepted by Varuna, god of hydrosphere. Varunastra is engineered to detect and help mitigate vulnerabilities in Docker, ensuring robust security across all Docker containers and images.

## Key Features

- **Secret Scanning:** Reduces the risk of sensitive data leaks.
- **Asset Extraction:** Retrieves assets such as domain/subdomains and urls from Docker images for bug bounty hunters.
- **Customizable Solution:** Define regex patterns and blacklists to meet specific needs.
- **Dependency Checks:** Automates assessments for quicker threat identification.

**Supported Lock Files**
| Language   | File                |
|------------|---------------------|
| Ruby       | Gemfile.lock        |
| Javascript | package-lock.json   |
|            | yarn.lock           |

**Supported Registry**
| Registry       | Scopes |
|----------------|--------|
| DockerHub      | Public |
| AWS ECR        | Public |
| Google GCR     | Public |
| Github GHCR    | Public |


### Installation Guide for Varunastra

You can install Varunastra in one of two ways: using Go or by downloading a pre-built binary.

#### Option 1: Install using Go

To install Varunastra using Go, run the following command:

```bash
go install github.com/Devang-Solanki/Varunastra/cmd/varunastra@latest
```

#### Option 2: Download Pre-built Binary
If you prefer to use a pre-built binary, you can download the appropriate version for your operating system and architecture from the release page.

#### Instructions to Download and Install

1. Download the appropriate .zip file for your OS and architecture.
2. Unzip the file to extract the binary.
3. Move the binary to a directory included in your system's PATH (e.g., /usr/local/bin for Linux or macOS).
4. Make the binary executable (if necessary):

```bash
chmod +x /path/to/varunastra
```

### Usage

```
Usage: varunastra --target=STRING [flags]

Varunastra is a tool designed to detect and assist in mitigating vulnerabilities within Docker images.

- For images hosted on Docker Hub, simply provide the repository name (e.g., `datadog/agent`).

- For images from AWS or GCP, include the full registry URL (e.g., `public.ecr.aws/hashicorp/vault`).

If no tag is specified in the repository URL, the tool will automatically choose a tag from the available options for scanning.

Note: Domains are resolved via DNS queries, while URLs are extracted using regular expressions without resolution.

Flags:
  -h, --help             Show context-sensitive help.
      --target=STRING    Target repos
      --scans=STRING     Comma-separated scans (secrets,vuln,assets). By default all scans are true if not specified any.
      --all              Enable scanning for all tags.
      --output=STRING    Save JSON output to a file
```


#### Example 

```bash
varunastra --target devangsolankii/secrets --scans "secrets,vuln,assets"
```

```
2024/11/04 12:29:37 Checking if config file exist
2024/11/04 12:29:39 Starting Scan for Tag: devangsolankii/secrets:v1.2
2024/11/04 12:29:39 Scanning Layer: sha256:51edc9808576655e8f3a0ce89e6d4d84eeba742af3376fc01d4522ecff379072
2024/11/04 12:29:39 Scanning Layer: sha256:59ee42d02ee5edca29b89e9d18b5bedd9400da38e1dcc0da4f22eaf19d24983b
2024/11/04 12:29:39 Scanning Layer: sha256:7d98d813d54f6207a57721008a4081378343ad8f1b2db66c121406019171805b
2024/11/04 12:29:39 Scanning Layer: sha256:da802df85c965baeca9d39869f9e2cbb3dc844d4627f413bfbb2f2c3d6055988
2024/11/04 12:29:39 Scanning Layer: sha256:e3d8693bad2fd07287529dd2f1bc71d431ed97f061cc8440707f144165fa8afc
2024/11/04 12:29:39 Scanning Layer: sha256:7aadc5092c3b7a865666b14bef3d4d038282b19b124542f1a158c98ea8c1ed1b
2024/11/04 12:29:39 Scanning Layer: sha256:eb173c1dbe92b367644a53adf5c004908921fa91460c054f2746046e481603fb
2024/11/04 12:29:39 Scanning Layer: sha256:d1d2216adb3bcbe1bb6f32f18f4b3a58350c5e2e7810728a488f405a444534ea
2024/11/04 12:29:39 Scanning Layer: sha256:f110c757afc5699d6587a989cc741d88e170d259506ecd3b6d9d0169c2dd1a47
2024/11/04 12:29:39 Scanning Layer: sha256:ad1c7cfc347f5c86fc2678b58f6a8fb6c6003471405760532fc3240b9eb1b343
2024/11/04 12:29:40
2024/11/04 12:29:40 Secrets found -> Type: Google API Key | Secret: AIzaSy0c3965368a6b10f7640dbda46abfdca98 | On Path: history:13
2024/11/04 12:29:40
2024/11/04 12:29:40 Secrets found -> Type: Google API Key | Secret: AIzaSy0c3965368a6b10f7640dbda46abfdca98 | On Path: history:18
2024/11/04 12:29:40 Scanning Layer: sha256:225e4516f59838f6d9e50e417461a30cce68d46786ee91df26e3c11e1eeb4948
2024/11/04 12:29:40 Scanning Layer: sha256:758f280dcc0fda3ba816ff06ff816511657120ea934adb600f3493c865a470cd
2024/11/04 12:29:40 Scanning Layer: sha256:4d5d29abf42d13611191d85daa10cc50bf2bde22d7bfd4f3de5447a5d888f14b
2024/11/04 12:29:40
2024/11/04 12:29:40 Secrets found -> Type: Password in URL | Secret: https://admmin:APA91b8uVvvpYoSJBCP@my.host.live.something.com:9000/" | On Path: app/app.js
2024/11/04 12:29:40
2024/11/04 12:29:40 Secrets found -> Type: PGP private key block | Secret: -----BEGIN PGP PRIVATE KEY BLOCK----- | On Path: etc/ImageMagick-6/mime.xml
2024/11/04 12:29:41
2024/11/04 12:29:41 Secrets found -> Type: AWS Access Key | Secret: ABIAK52LPFORPRUCRC22 | On Path: app/.env
2024/11/04 12:31:13 Scanning completed.
[
  {
    "target": "devangsolankii/secrets:v1.2",
    "secrets": [
      {
        "issue": "Secret Leaked in Docker Layer sha256:758f280dcc0fda3ba816ff06ff816511657120ea934adb600f3493c865a470cd",
        "asset": "app/.env",
        "type": "AWS Access Key",
        "secret": "ABIAK52LPFORPRUCRC22"
      },
      {
        "issue": "Secret Leaked in Docker History history:13",
        "asset": "history:13",
        "type": "Google API Key",
        "secret": "AIzaSy0c3965368a6b10f7640dbda46abfdca98"
      },
      {
        "issue": "Secret Leaked in Docker History history:18",
        "asset": "history:18",
        "type": "Google API Key",
        "secret": "AIzaSy0c3965368a6b10f7640dbda46abfdca98"
      },
      {
        "issue": "Secret Leaked in Docker Layer sha256:ad1c7cfc347f5c86fc2678b58f6a8fb6c6003471405760532fc3240b9eb1b343",
        "asset": "etc/ImageMagick-6/mime.xml",
        "type": "PGP private key block",
        "secret": "-----BEGIN PGP PRIVATE KEY BLOCK-----"
      },
      {
        "issue": "Secret Leaked in Docker Layer sha256:225e4516f59838f6d9e50e417461a30cce68d46786ee91df26e3c11e1eeb4948",
        "asset": "app/app.js",
        "type": "Password in URL",
        "secret": "https://admmin:APA91b8uVvvpYoSJBCP@my.host.live.something.com:9000/\"\n"
      }
    ],
    "vulnerabilities": null,
    "assets": {
      "assets": [],
      "urls": []
    }
  }
]
```

<a href="https://www.buymeacoffee.com/devangsolankii" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174" /></a>
