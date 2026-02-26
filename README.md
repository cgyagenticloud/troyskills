# TroySkills.ai

⚠️ **AI Agent Malicious Skills Database** — Like CVE/NVD, but for AI agent skills.

## What is TroySkills?

TroySkills is a public database documenting malicious AI agent skill patterns. We collect, classify, and publish attack patterns to protect the AI agent ecosystem.

## Attack Categories

| ID | Category | Description |
|----|----------|-------------|
| P1 | Prompt Injection | Skills that override agent system prompts |
| P2 | Data Exfiltration | Skills that steal data and credentials |
| P3 | Privilege Escalation | Skills that gain elevated access |
| P4 | Malicious Scripts | Skills containing malware |
| P5 | Config Tampering | Skills that poison agent configuration |
| P6 | Social Engineering | Skills that abuse messaging capabilities |
| P7 | Supply Chain | Skills that exploit the distribution chain |

## Tech Stack

- [Astro](https://astro.build) — Static site generator
- [Tailwind CSS](https://tailwindcss.com) — Styling
- [Cloudflare Pages](https://pages.cloudflare.com) — Hosting

## Development

```bash
npm install
npm run dev      # Start dev server
npm run build    # Build for production
```

## Contributing

Report new attack patterns by opening an issue or submitting a PR.

## License

MIT
