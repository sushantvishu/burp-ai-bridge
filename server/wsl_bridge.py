import subprocess
import json
import re
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urlparse

WSL_OUTPUT_ENCODING = "utf-8"
WSL_OUTPUT_ERRORS = "replace"


class WSLBridge:
    def __init__(self, base_dir: str = ".."):
        # Setup output directory for scans
        self.scans_dir = Path(base_dir) / "out" / "scans"
        self.scans_dir.mkdir(parents=True, exist_ok=True)

    def _safe_domain(self, url: str) -> str:
        """Extract a safe filename from a URL."""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        return re.sub(r"[^a-zA-Z0-9.-]", "_", domain)

    def run_command(self, cmd_list: list) -> str:
        """Executes a command inside WSL and returns the stdout."""
        try:
            # We prefix the command with 'wsl' to execute it in the default Linux distribution
            full_cmd = ["wsl"] + cmd_list
            print(f"[*] Executing in WSL: {' '.join(full_cmd)}")
            
            result = subprocess.run(
                full_cmd, 
                capture_output=True, 
                text=True, 
                encoding=WSL_OUTPUT_ENCODING,
                errors=WSL_OUTPUT_ERRORS,
                timeout=300 # 5 minute timeout for recon tools
            )
            
            if result.returncode != 0:
                print(f"[!] WSL Command Error: {result.stderr}")
                return result.stderr

            return result.stdout
        except Exception as e:
            return f"Error executing WSL command: {str(e)}"

    def run_nuclei(self, target_url: str, tags: str = "cves,vuln,exposures") -> Dict[str, Any]:
        """Runs Nuclei via WSL, captures JSON output, and saves it."""
        domain = self._safe_domain(target_url)
        output_file = self.scans_dir / f"nuclei_{domain}.json"
        
        # We run nuclei in silent mode, outputting JSON strings
        cmd = ["nuclei", "-u", target_url, "-tags", tags, "-silent", "-jsonl"]
        
        stdout = self.run_command(cmd)
        
        # Parse the JSON lines into a list of findings
        findings = []
        for line in stdout.strip().splitlines():
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        
        # Save to out/scans/
        output_file.write_text(json.dumps(findings, indent=2), encoding=WSL_OUTPUT_ENCODING)
        print(f"[+] Nuclei scan saved to {output_file}")
        
        return {
            "target": target_url,
            "tool": "nuclei",
            "findings_count": len(findings),
            "findings": findings
        }

    def run_nmap_top_ports(self, target_ip: str) -> str:
        """Runs a quick nmap scan on top ports."""
        cmd = ["nmap", "-F", "-sV", "-T4", target_ip]
        stdout = self.run_command(cmd)
        
        output_file = self.scans_dir / f"nmap_{self._safe_domain(target_ip)}.txt"
        output_file.write_text(stdout, encoding=WSL_OUTPUT_ENCODING)
        
        return stdout

# Example Usage for testing:
# if __name__ == "__main__":
#     bridge = WSLBridge()
#     print(bridge.run_nuclei("http://example.com"))
