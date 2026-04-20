nexus-mcp/
├── configs/
│   ├── claude_bugbounty.json
│   ├── claude_cloud.json
│   ├── claude_ctf.json
│   ├── claude_full.json
│   ├── claude_recon.json
│   └── claude_web.json
├── src/
│   ├── cache.ts
│   ├── executor.ts
│   ├── index.ts
│   ├── memory.ts
│   ├── parsers/
│   │   ├── ffuf.ts
│   │   ├── index.ts
│   │   ├── nikto.ts
│   │   ├── nmap.ts
│   │   ├── nuclei.ts
│   │   ├── sqlmap.ts
│   │   └── subfinder.ts
│   ├── profiles.ts
│   ├── registry.ts
│   ├── server.ts
│   ├── tools/
│   │   ├── auth.ts
│   │   ├── binary.ts
│   │   ├── cloud.ts
│   │   ├── exploit.ts
│   │   ├── forensics.ts
│   │   ├── meta.ts
│   │   ├── network.ts
│   │   ├── osint.ts
│   │   ├── recon.ts
│   │   ├── webattack.ts
│   │   └── web.ts
│   ├── types.ts
│   └── utils/
│       ├── clean.ts
│       ├── detect.ts
│       └── wordlists.ts
├── .env
├── .gitignore
├── package.json
├── package-lock.json
├── README.md
└── tsconfig.json
