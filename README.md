<p align="center">
  <img src="public/favicon.svg" width="80" alt="TroySkills Logo" />
</p>

<h1 align="center">TroySkills.ai</h1>

<p align="center">
  <strong>The first comprehensive database of AI agent attack patterns</strong><br>
  <em>Like CVE/NVD, but for AI agent skills</em>
</p>

<p align="center">
  <a href="https://github.com/cgyagenticloud/troyskills/stargazers"><img src="https://img.shields.io/github/stars/cgyagenticloud/troyskills?style=flat-square&color=red" alt="Stars"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/patterns-150-red?style=flat-square" alt="Patterns">
  <img src="https://img.shields.io/badge/categories-7-orange?style=flat-square" alt="Categories">
  <img src="https://img.shields.io/badge/built%20with-Astro-purple?style=flat-square" alt="Astro">
</p>

<p align="center">
  <a href="https://troyskills.ai">🌐 Live Site</a> ·
  <a href="https://troyskills.ai/database">📊 Database</a> ·
  <a href="https://troyskills.ai/executive-summary">📋 Executive Summary</a> ·
  <a href="https://troyskills.ai/defense">🛡️ Defense Playbook</a>
</p>

---

## What is TroySkills?

TroySkills documents, classifies, and publishes **malicious AI agent skill patterns** — the techniques attackers use to weaponize AI agent tools and capabilities. As AI agents gain access to code, finances, infrastructure, and communications, understanding these attack vectors is critical for every organization.

**150 attack patterns** across **7 categories**, each with:
- Detailed technical writeup and attack vector description
- Working code examples demonstrating the attack
- Impact assessment and severity rating
- Specific, actionable mitigations

## Attack Categories

| ID | Category | Count | Description |
|----|----------|-------|-------------|
| **P1** | Prompt Injection | 22 | Skills that override agent system prompts |
| **P2** | Data Exfiltration | 24 | Skills that steal data and credentials |
| **P3** | Privilege Escalation | 20 | Skills that gain elevated access |
| **P4** | Malicious Scripts | 20 | Skills containing malware/destructive code |
| **P5** | Config Tampering | 22 | Skills that poison agent configuration |
| **P6** | Social Engineering | 20 | Skills that abuse messaging capabilities |
| **P7** | Supply Chain | 22 | Skills that exploit the distribution chain |

## Screenshots

> *Screenshots coming soon — visit [troyskills.ai](https://troyskills.ai) to see the live site*

<!--
<p align="center">
  <img src="docs/screenshots/homepage.png" width="700" alt="Homepage" />
  <img src="docs/screenshots/database.png" width="700" alt="Database" />
</p>
-->

## Quick Start

```bash
# Clone the repository
git clone https://github.com/cgyagenticloud/troyskills.git
cd troyskills

# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

The site runs at `http://localhost:4321` in development mode.

## Project Structure

```
troyskills-site/
├── src/
│   ├── content/
│   │   └── skills/           # 150 attack pattern markdown files
│   │       ├── TS-2026-0001.md
│   │       ├── TS-2026-0002.md
│   │       └── ...
│   ├── layouts/
│   │   └── Layout.astro      # Base layout with nav, footer, dark theme
│   ├── pages/
│   │   ├── index.astro        # Homepage
│   │   ├── database.astro     # Searchable pattern database
│   │   ├── executive-summary.astro  # Print-ready infographic
│   │   ├── defense.astro      # Defense playbook
│   │   ├── checklist.astro    # Security checklist
│   │   ├── simulator.astro    # Attack simulator
│   │   ├── stats.astro        # Statistics dashboard
│   │   ├── timeline.astro     # Attack timeline
│   │   ├── threat-model.astro # Threat modeling guide
│   │   └── skill/
│   │       └── [...id].astro  # Dynamic pattern detail pages
│   └── styles/                # Global styles
├── public/                    # Static assets
├── astro.config.mjs           # Astro configuration
├── tailwind.config.mjs        # Tailwind CSS configuration
└── package.json
```

## How to Add a Pattern

1. Create a new markdown file in `src/content/skills/`:

```bash
touch src/content/skills/TS-2026-0151.md
```

2. Add frontmatter and content following this template:

```markdown
---
id: "TS-2026-0151"
title: "Your Attack Pattern Title"
category: "P1"  # P1-P7
severity: "Critical"  # Critical, High, Medium, Low
description: "One-line description of the attack."
date: "2026-02-26"
tags: ["tag1", "tag2", "tag3"]
---

## Overview

Detailed explanation of the attack pattern.

## Attack Vector

1. Step-by-step attack flow
2. How the attacker gains access
3. What happens during the attack

## Technical Details

\```python
# Working code example demonstrating the attack
\```

## Impact

- **Impact 1** — description
- **Impact 2** — description

## Mitigation

- Specific defensive measure 1
- Specific defensive measure 2
- See also: [TS-2026-XXXX](/skill/TS-2026-XXXX)
```

3. Build and verify:

```bash
npm run build
```

The pattern will automatically appear in the database, stats, and navigation.

## Contributing

We welcome contributions! Here's how to help:

1. **Add new patterns** — Discovered a new AI agent attack vector? Document it following the template above.
2. **Improve existing patterns** — Better code examples, additional mitigations, clearer explanations.
3. **Report issues** — Found an error or broken link? Open an issue.
4. **Spread the word** — Star the repo, share with your security team.

### Contribution Process

1. Fork the repository
2. Create a feature branch: `git checkout -b add-pattern-0151`
3. Add or modify patterns following the template
4. Build and verify: `npm run build`
5. Submit a pull request with a clear description

### Guidelines

- Each pattern should have a unique `TS-2026-XXXX` ID
- Include working code examples (use `evil.example.com` for attacker domains)
- Severity ratings: **Critical** (immediate risk), **High** (significant risk), **Medium** (moderate risk), **Low** (informational)
- Cross-reference related patterns with `See also` links
- Keep descriptions factual and technical — this is a security resource, not a hacking guide

## Tech Stack

- **[Astro](https://astro.build)** — Static site generator
- **[Tailwind CSS](https://tailwindcss.com)** — Utility-first CSS
- **Markdown** — Content format for all patterns
- **[Cloudflare Pages](https://pages.cloudflare.com)** — Hosting & CDN

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

Attack patterns are published for **defensive security research purposes only**. Use this knowledge to protect your systems, not to attack others.

## Credits

- **Created by** [TroySkills Team](https://troyskills.ai) — AI agent security researchers
- **Built with** [Astro](https://astro.build) + [Tailwind CSS](https://tailwindcss.com)
- **Inspired by** [MITRE ATT&CK](https://attack.mitre.org), [CVE](https://cve.mitre.org), and [OWASP](https://owasp.org)
- **Hosting** [Cloudflare Pages](https://pages.cloudflare.com)

---

<p align="center">
  <strong>⚠️ AI agents are powerful. Make sure they're not weaponized against you.</strong><br>
  <a href="https://troyskills.ai">troyskills.ai</a>
</p>
