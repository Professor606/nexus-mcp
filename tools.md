# Nexus MCP Toolset

This project integrates a wide range of security and penetration testing tools into the Model Context Protocol (MCP) framework. Below is a comprehensive list of the supported tools categorized by their function.

## Web Scanning & Discovery
- **[ffuf](https://github.com/ffuf/ffuf)**: Fast web fuzzer for directory and file discovery.
- **[feroxbuster](https://github.com/epi052/feroxbuster)**: Fast, simple, recursive content discovery.
- **[httpx](https://github.com/projectdiscovery/httpx)**: Fast and multi-purpose HTTP toolkit for prober and tech detection.
- **[katana](https://github.com/projectdiscovery/katana)**: Next-generation crawling and spidering framework.
- **[gau](https://github.com/lc/gau)**: Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl.
- **[nuclei](https://github.com/projectdiscovery/nuclei)**: Fast and customizable vulnerability scanner based on simple YAML-based DSL.
- **[nikto](https://github.com/sullo/nikto)**: Web server scanner which performs comprehensive tests against web servers.
- **[whatweb](https://github.com/urbanadventurer/WhatWeb)**: Next generation web scanner that identifies technologies.
- **[wafw00f](https://github.com/EnableSecurity/wafw00f)**: Identify and fingerprint Web Application Firewalls (WAF).
- **[testssl](https://github.com/drwetter/testssl.sh)**: Command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some recent vulnerabilities.

## Network Enumeration & Exploitation
- **[enum4linux-ng](https://github.com/cddo/enum4linux-ng)**: Next generation version of enum4linux (Windows/Samba enumeration).
- **[netexec](https://github.com/PennyWise-Systems/NetExec)** (or **nxc**): Network service exploitation tool.
- **[smbmap](https://github.com/ShawnDEvans/smbmap)**: Handy SMB enumeration tool.
- **[responder](https://github.com/lgandx/Responder)**: LLMNR, NBT-NS and MDNS poisoner.

## Authentication & Cracking
- **[hydra](https://github.com/vanhauser-thc/thc-hydra)**: Fast network logon cracker.
- **[hashcat](https://github.com/hashcat/hashcat)**: World's fastest and most advanced password recovery utility.
- **[john](https://github.com/openwall/john)**: John the Ripper password cracker.
- **[hashid](https://github.com/psypanda/hashid)**: Identify the different types of hashes.
- **[evil-winrm](https://github.com/Hackplayers/evil-winrm)**: WinRM shell for pentesting.

## Binary Analysis & Forensics
- **[gdb](https://www.gnu.org/software/gdb/)**: GNU Debugger for script automation.
- **[radare2](https://github.com/radareorg/radare2)** (`r2`): Advanced commandline hex editor and disassembler.
- **[ghidra](https://github.com/NationalSecurityAgency/ghidra)** (`analyzeHeadless`): Ghidra headless analyzer.
- **[binwalk](https://github.com/ReFirmLabs/binwalk)**: Firmware analysis and extraction tool.
- **[checksec](https://github.com/slimm609/checksec.sh)**: Check binary for security properties.
- **strings**: Extract printable strings from files.
- **readelf**: Analyze ELF file headers and sections.
- **[ropper](https://github.com/sashs/Ropper)**: ROP gadget finder and binary information tool.
- **[one_gadget](https://github.com/david942j/one_gadget)**: Find one-shot RCE gadgets in libc.
- **[volatility3](https://github.com/volatilityfoundation/volatility3)**: Memory forensics framework.
- **[foremost](https://github.com/corsec/foremost)**: File carving tool.
- **[steghide](https://github.com/NedkoNev/steghide)**: Steganography extraction tool.
- **[zsteg](https://github.com/zed-0xff/zsteg)**: PNG/BMP steganography LSB analysis.
- **[exiftool](https://github.com/exiftool/exiftool)**: Read and write file metadata.
- **[rsatool](https://github.com/ius/rsatool)**: RSA key analysis and private key generation from known parameters.

## Cloud & Infrastructure
- **[prowler](https://github.com/prowler-cloud/prowler)**: Cloud security assessments, audits, incident response.
- **[trivy](https://github.com/aquasecurity/trivy)**: Comprehensive vulnerability scanner for containers and other artifacts.
- **[kube-hunter](https://github.com/aquasecurity/kube-hunter)**: Hunt for security weaknesses in Kubernetes clusters.
- **[pacu](https://github.com/RhinoSecurityLabs/pacu)**: AWS exploitation framework.

## Exploitation & OSINT
- **[pwntools](https://github.com/Gallopsled/pwntools)**: CTF framework and exploit development library.
- **[angr](https://github.com/angr/angr)**: Multi-architecture binary analysis platform.
- **[libc-database](https://github.com/niklasb/libc-database)**: Lookup libc version from leaked addresses.
- **[sherlock](https://github.com/sherlock-project/sherlock)**: Hunt down social media accounts by username.
- **[trufflehog](https://github.com/trufflesecurity/trufflehog)**: Find credentials in code and history.
- **[spiderfoot](https://github.com/smicallef/spiderfoot)**: OSINT automation tool.
- **[shodan](https://github.com/achillean/shodan-python)**: Search Shodan via CLI.

## Reconnaissance
- **[nmap](https://github.com/nmap/nmap)**: Port scan, service detection, OS fingerprint, and NSE scripts.
- **[rustscan](https://github.com/RustScan/RustScan)**: Fast port scanner that pipes to nmap.
- **[subfinder](https://github.com/projectdiscovery/subfinder)**: Fast passive subdomain enumeration.
- **[amass](https://github.com/owasp-amass/amass)**: In-depth attack surface mapping and asset discovery.
- **[theHarvester](https://github.com/laramies/theHarvester)**: E-mails, subdomains and names OSINT.

## Web Attack Tools
- **[sqlmap](https://github.com/sqlmapproject/sqlmap)**: Automated SQL injection and database takeover tool.
- **[dalfox](https://github.com/hahwul/dalfox)**: Fast, powerful XSS scanner and utility tool.
- **[arjun](https://github.com/s0md3v/Arjun)**: HTTP parameter discovery suite.
- **[x8](https://github.com/Sh1Yo/x8)**: Hidden parameter discovery suite.
- **[wpscan](https://github.com/wpscanteam/wpscan)**: Black box WordPress vulnerability scanner.
- **[nosqlmap](https://github.com/codingo/NoSQLMap)**: Automated NoSQL database exploitation.
- **[tplmap](https://github.com/epinna/tplmap)**: Server-side template injection and Web server exploitation.
- **[commix](https://github.com/commixproject/commix)**: Automated OS command injection exploitation tool.
- **[jwt_tool](https://github.com/ticarpi/jwt_tool)**: Toolkit for validating, forging and cracking JWTs.
- **[subjack](https://github.com/haccer/subjack)**: Hostile subdomain takeover vulnerability scanner.

## Nexus MCP Internal Tools
- **switch_phase**: Switch between tool profiles (recon, web, network, etc.).
- **pentest_notes**: Save, load, and manage structured pentest findings.
- **chain_tools**: Run multiple tools in sequence, feeding findings forward.
- **attack_chain_suggest**: Get AI-driven suggestions for next steps based on findings.
- **generate_report**: Create a comprehensive markdown pentest report from session data.
