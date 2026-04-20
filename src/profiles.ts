import type { Profile } from "./types.js";

/**
 * Maps profiles to their respective tool names.
 * Tools are registered unconditionally at startup;
 * the profile string filters what the LLM sees via ListTools.
 */
export const PROFILES: Record<Profile, string[]> = {
  recon: [
    "nmap_scan", "rustscan_scan", "subfinder_scan", "amass_enum",
    "theharvester_scan", "httpx_probe", "katana_crawl", "gau_urls",
    "whatweb_detect", "wafw00f_detect", "shodan_search"
  ],
  web: [
    "ffuf_scan", "feroxbuster_scan", "httpx_probe", "nuclei_scan", "nikto_scan",
    "sqlmap_scan", "dalfox_scan", "arjun_discover", "x8_discover",
    "wpscan_scan", "nosqlmap_scan", "tplmap_scan", "commix_scan",
    "jwt_tool_test", "testssl_scan", "whatweb_detect"
  ],
  network: [
    "nmap_scan", "rustscan_scan", "enum4linux_ng_scan", "netexec_run",
    "smbmap_scan", "responder_run", "hydra_crack", "evil_winrm_shell"
  ],
  bugbounty: [
    "subfinder_scan", "amass_enum", "httpx_probe", "katana_crawl", "gau_urls",
    "ffuf_scan", "nuclei_scan", "dalfox_scan", "arjun_discover", "x8_discover",
    "subjack_check", "trufflehog_scan", "shodan_search", "wafw00f_detect",
    "whatweb_detect", "jwt_tool_test", "wpscan_scan", "testssl_scan"
  ],
  ctf: [
    "gdb_debug", "radare2_analyze", "ghidra_analyze", "binwalk_extract",
    "checksec_check", "binary_info", "ropper_find", "one_gadget_find",
    "pwntools_run", "angr_analyze", "libc_database_lookup",
    "volatility3_analyze", "foremost_carve", "steghide_extract",
    "zsteg_analyze", "exiftool_read", "rsatool_analyze",
    "hashcat_crack", "john_crack", "hashid_identify"
  ],
  cloud: [
    "prowler_assess", "trivy_scan", "kube_hunter_scan", "pacu_run"
  ],
  osint: [
    "sherlock_search", "spiderfoot_scan", "shodan_search",
    "trufflehog_scan", "theharvester_scan"
  ],
  full: [] // Special case: allows all tools
};
