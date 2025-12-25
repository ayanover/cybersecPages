# Advanced Cybersecurity Course

Comprehensive advanced cybersecurity training documentation covering offensive security, defensive security, application security, and cloud infrastructure security.

## Overview

This project provides in-depth guides and documentation for advanced cybersecurity topics across four major domains:

- **Offensive Security**: Penetration testing, exploit development, red teaming, and vulnerability research
- **Defensive Security**: Threat detection, incident response, SIEM, SOC operations, and threat hunting
- **Application Security**: Secure coding, web/mobile/API security, and code review practices
- **Cloud & Infrastructure**: AWS/Azure/GCP security, container security, Kubernetes, and infrastructure hardening

## Quick Start

### Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cybersec.git
   cd cybersec
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Serve locally with hot-reload:
   ```bash
   mkdocs serve
   ```

4. View at: http://127.0.0.1:8000

### Building

Build the static site:
```bash
mkdocs build
```

The built site will be in the `site/` directory.

### Deployment

The site automatically deploys to GitHub Pages when changes are pushed to the main branch via GitHub Actions.

Manual deployment:
```bash
mkdocs gh-deploy
```

## Documentation Structure

### Offensive Security
- Penetration Testing (methodology, reconnaissance, enumeration, exploitation, post-exploitation, reporting)
- Exploit Development (buffer overflows, shellcode, ROP, heap exploitation, fuzzing)
- Red Teaming (adversary emulation, C2 frameworks, evasion, persistence, lateral movement)
- Vulnerability Research (static/dynamic analysis, reverse engineering, patch diffing)
- Tools & Frameworks (Metasploit, Cobalt Strike, Burp Suite, custom tooling)

### Defensive Security
- Threat Detection (network/endpoint monitoring, behavioral analysis, anomaly detection, threat intelligence)
- Incident Response (IR framework, preparation, identification, containment, eradication, recovery, forensics)
- SIEM & Log Management (Splunk, ELK Stack, Sentinel, log correlation, use cases)
- SOC Operations (SOC structure, alert triage, playbooks, metrics, automation)
- Threat Hunting (hypothesis-driven hunting, threat models, techniques, MITRE ATT&CK)
- Blue Team Tools (IDS/IPS, EDR, network security, SOAR)

### Application Security
- Secure Coding (Secure SDLC, input validation, authentication, authorization, cryptography, session management)
- Web Security (OWASP Top 10, SQL injection, XSS, CSRF, SSRF, XXE, file uploads, auth flaws)
- Mobile Security (Android, iOS, Mobile OWASP, reverse engineering, secure development)
- API Security (REST, GraphQL, authentication, rate limiting, testing)
- Code Review (manual review, SAST, DAST, SCA, secure patterns)
- AppSec Tools (Burp Suite Pro, OWASP ZAP, Semgrep, SonarQube)

### Cloud & Infrastructure
- AWS Security (IAM, VPC, S3, EC2, Lambda, CloudTrail, Security Hub)
- Azure Security (Azure AD, networking, storage, VMs, Defender for Cloud, Sentinel)
- GCP Security (IAM, VPC, storage, compute, Security Command Center)
- Container Security (Docker, image scanning, runtime security, registries)
- Kubernetes Security (cluster hardening, RBAC, network policies, pod security, secrets, admission controllers)
- Infrastructure Hardening (Linux/Windows hardening, network segmentation, zero trust, compliance)
- Cloud Tools (Terraform, Ansible, CSPM, IaC scanning)

## Features

- Professional Material Design theme
- Dark/light mode toggle
- Full-text search with suggestions
- Syntax-highlighted code examples
- Mermaid diagrams for visualizations
- Mobile-responsive design
- Automatic last-update timestamps
- Navigation tabs for major domains
- Expandable sections and collapsible admonitions

## Technology Stack

- **MkDocs**: Static site generator
- **Material for MkDocs**: Professional documentation theme
- **GitHub Pages**: Free hosting
- **GitHub Actions**: Automated CI/CD deployment
- **Python Markdown Extensions**: Enhanced formatting capabilities

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-content`
3. Add your content following the existing structure
4. Test locally: `mkdocs serve`
5. Commit your changes: `git commit -m "Add new content on [topic]"`
6. Push to your fork: `git push origin feature/new-content`
7. Submit a pull request

### Content Guidelines

- Follow the established page template structure
- Include practical examples with code snippets
- Add diagrams where helpful (using Mermaid)
- Cite authoritative sources
- Ensure technical accuracy
- Write clear, concise explanations

## Project Structure

```
cybersec/
├── .github/workflows/     # GitHub Actions CI/CD
├── docs/                  # Documentation source files
│   ├── offensive-security/
│   ├── defensive-security/
│   ├── application-security/
│   ├── cloud-infrastructure/
│   ├── resources/
│   ├── code-examples/
│   └── assets/           # Images, CSS, JavaScript
├── mkdocs.yml            # MkDocs configuration
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## License

[Choose an appropriate license - MIT, Apache 2.0, CC BY-SA, etc.]

## Acknowledgments

Built with [MkDocs](https://www.mkdocs.org/) and [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/).

## Contact

For questions, suggestions, or feedback:
- GitHub Issues: https://github.com/yourusername/cybersec/issues
- Email: your.email@example.com
