# Burp AI Bridge

Burp AI Bridge is a two-part local advisory workflow:

- `burp-extension/` is the Burp Suite Pro extension built with the Montoya API.
- `server/` is the local FastAPI backend that sends selected HTTP traffic to a local Ollama model and returns structured guidance.

The intended operating model is human-in-the-loop security testing. The extension helps you triage captured traffic, identify likely follow-up areas, suggest `nuclei` tags and `SecLists` paths, and capture operator constraints before you run tooling manually in Kali WSL.

## Project Layout

```text
burp-ai-bridge/
|- burp-extension/
|- server/
|- kb/
|- rag/
`- out/
```

Key files:

- `burp-extension/src/main/java/com/example/burpaibridge/BurpAiBridgeExtension.java`
- `burp-extension/src/main/java/com/example/burpaibridge/BridgeClient.java`
- `burp-extension/src/main/java/com/example/burpaibridge/ResultsTab.java`
- `server/main.py`
- `server/ai_client.py`
- `server/rag_engine.py`
- `server/wsl_bridge.py`

## Execution Model

1. Burp Suite sends a selected request/response pair to `http://127.0.0.1:8000/api/analyze`.
2. The FastAPI server receives the payload.
3. The server sends a prompt to Ollama at `http://127.0.0.1:11434/api/generate` using the `qwen2.5-coder:3b` model by default unless `OLLAMA_MODEL` is overridden.
4. The model returns structured JSON containing:
   - an advisory analysis
   - potential vulnerabilities
   - recommended `nuclei` tags
   - a suggested `SecLists` path
   - clarifying questions for the operator
5. You review the guidance in Burp and then decide what to run manually in Kali WSL.

## Prerequisites

### Windows host

Install and verify the following on the Windows machine that runs Burp Suite Pro and the Python server:

- Python 3.10 or newer
- Burp Suite Pro
- Ollama for Windows
- WSL2 with a Kali Linux distribution

Recommended project root on Windows:

```powershell
D:\burp-ai-bridge-main\burp-ai-bridge-main
```

### Python dependencies on Windows

Open Windows PowerShell and run:

```powershell
cd D:\burp-ai-bridge-main\burp-ai-bridge-main
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r server/requirements.txt
```

Notes:

- `beautifulsoup4` is needed by `server/rag_engine.py`.
- `lxml` is recommended because the scraper uses `BeautifulSoup(..., "lxml")`.

### Kali WSL tools

Open Kali WSL and install the required tooling:

```bash
sudo apt update
sudo apt install -y nuclei ffuf seclists nmap unzip zip curl
nuclei -update-templates
```

Verify the tools:

```bash
which nuclei
which ffuf
ls /usr/share/seclists
nuclei -version
ffuf -V
```

If SDKMAN is not already installed in Kali WSL, install it:

```bash
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
```

Install Java and Gradle for the Burp extension build:

```bash
sdk install java 21.0.6-tem
sdk install gradle 9.0.0
java -version
gradle -version
```

## Starting the Brain

The "brain" is the combination of Ollama plus the FastAPI server.

### 1. Ensure Ollama is serving `qwen2.5-coder:3b` on port 11434

Open Windows PowerShell:

```powershell
ollama pull qwen2.5-coder:3b
ollama serve
```

Ollama serves on `127.0.0.1:11434` by default. In a second PowerShell window, verify the model is available:

```powershell
ollama list
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:11434/api/tags
```

If you already have Ollama running as a background service, you do not need to start `ollama serve` again. You only need to verify that:

- port `11434` is reachable on localhost
- `qwen2.5-coder:3b` is present in `ollama list`

### 2. Start the FastAPI server on port 8000

Open Windows PowerShell in the project root:

```powershell
cd D:\burp-ai-bridge-main\burp-ai-bridge-main
.\.venv\Scripts\Activate.ps1
python -m uvicorn server.main:app --reload --host 127.0.0.1 --port 8000
```

Expected result:

- Uvicorn binds to `http://127.0.0.1:8000`
- the Burp extension can reach `http://127.0.0.1:8000/api/analyze`

Optional health check in another PowerShell window:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/docs
```

## Building the Client

Build the Burp extension JAR inside Kali WSL using SDKMAN-managed Java and Gradle.

### 1. Open Kali WSL and change into the project

```bash
cd /mnt/d/burp-ai-bridge-main/burp-ai-bridge-main/burp-extension
```

### 2. Initialize SDKMAN and set the WSL networking workarounds

These two exports are required because you explicitly asked for the WSL Java/Gradle networking fixes.

```bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
export _JAVA_OPTIONS="-Djava.net.preferIPv4Stack=true"
export GRADLE_OPTS="-Dorg.gradle.daemon=false"
```

### 3. Build the JAR with Gradle

```bash
gradle clean build
```

Expected artifact:

```text
/mnt/d/burp-ai-bridge-main/burp-ai-bridge-main/burp-extension/build/libs/burp-ai-bridge-0.2.0.jar
```

Optional verification:

```bash
ls -l /mnt/d/burp-ai-bridge-main/burp-ai-bridge-main/burp-extension/build/libs/
```

If the build fails because Java or Gradle is missing, rerun:

```bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk use java 21.0.6-tem
sdk use gradle 9.0.0
export _JAVA_OPTIONS="-Djava.net.preferIPv4Stack=true"
export GRADLE_OPTS="-Dorg.gradle.daemon=false"
gradle clean build
```

## Loading into Burp Suite Pro

1. Start Burp Suite Pro on Windows.
2. Go to `Extender`.
3. Open the `Extensions` sub-tab.
4. Click `Add`.
5. Set `Extension type` to `Java`.
6. Click `Select file...`.
7. Choose the built JAR:

```text
D:\burp-ai-bridge-main\burp-ai-bridge-main\burp-extension\build\libs\burp-ai-bridge-0.2.0.jar
```

8. Confirm the dialog.
9. Check Burp's extension output for the message:

```text
AI Bridge loaded. Advisory workflow enabled.
```

10. Confirm a new Burp tab named `AI Bridge` is visible.

Default bridge endpoint shown in the UI:

```text
http://127.0.0.1:8000/api/analyze
```

If you changed the server host or port, update the endpoint field inside the Burp tab before sending traffic.

## The Consultant Workflow (Usage)

This is the intended operating workflow for a manual assessment.

### 1. Capture a request in Burp

Use Burp Proxy, HTTP history, Repeater, or another Burp tool to obtain a request/response pair you want to triage.

### 2. Send the traffic to the AI Bridge

In Burp:

1. Right-click the request entry.
2. Click `Send to AI Bridge`.
3. Switch to the `AI Bridge` tab.

What happens next:

- the extension serializes the raw request and, if present, the raw response
- it includes the target URL and HTTP method
- it posts the payload to the FastAPI server

### 3. Review the advisory response

In the `AI Bridge` tab, review:

- `AI Analysis`: the model's summary of the traffic and likely areas of interest
- `Potential Vulnerabilities`: candidate issues worth manual validation
- `Nuclei Tags`: the tags you can use to focus a Nuclei run
- `SecLists Path`: a wordlist suggestion for manual enumeration
- `Operator Constraints and Clarifying Answers`: the questions the AI wants you to answer before follow-up work

Typical examples of clarifying questions:

- What is the rate limit?
- Is there a WAF?
- Are authentication headers required?
- Is the endpoint multi-tenant?

### 4. Answer the AI's questions in Burp

Type your answers directly into the fields shown under `Operator Constraints and Clarifying Answers`.

Examples:

- `Rate limit: 5 requests per second before 429`
- `Auth header required: Authorization: Bearer <token>`
- `WAF present: Cloudflare managed challenge after burst traffic`

Useful controls in the tab:

- `Clear Answers` resets the answer fields.
- `Copy Answers as JSON` copies your answers to the clipboard.

Important implementation note:

- The current UI captures your answers and can submit them back to the local server for a second-pass advisory follow-up.
- Treat the answers as operator-supplied context that sharpens the next advisory, not as a replacement for manual validation.

### 5. Run the recommended tools manually in Kali WSL

Use the AI output as guidance, not as an automatic scanner.

#### Example: run Nuclei with the suggested tags

If the tab suggests tags such as `xss,sqli,cve`, run:

```bash
cd /mnt/d/burp-ai-bridge-main/burp-ai-bridge-main
nuclei -u "https://target.example" -tags xss,sqli,cve -silent -jsonl | tee out/scans/nuclei_target_example.jsonl
```

#### Example: run ffuf with the suggested SecLists wordlist

If the tab suggests `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt`, run:

```bash
ffuf -u "https://target.example/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc all -fc 404
```

#### Example: use custom headers from your Burp observations

```bash
ffuf -u "https://target.example/api/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -H "Authorization: Bearer <token>" -H "X-Forwarded-For: 127.0.0.1"
```

#### Example: conservative Nmap top-port validation against an IP target

```bash
nmap -F -sV -T4 target-ip-or-hostname
```

### 6. Correlate manual findings with Burp observations

Use the Burp request/response pair, the AI guidance, and the Kali tool output together. The extension is advisory. You are still responsible for:

- validating whether a suspected issue is real
- controlling scan rate and headers safely
- staying within scope and authorization
- deciding which manual follow-up is justified

## Full Startup Sequence

If you want the shortest end-to-end execution path, use this exact order.

### Windows PowerShell window 1

```powershell
ollama pull qwen2.5-coder:3b
ollama serve
```

### Windows PowerShell window 2

```powershell
cd D:\burp-ai-bridge-main\burp-ai-bridge-main
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r server/requirements.txt
python -m uvicorn server.main:app --reload --host 127.0.0.1 --port 8000
```

### Kali WSL terminal

```bash
sudo apt update
sudo apt install -y nuclei ffuf seclists nmap unzip zip curl
nuclei -update-templates
source "$HOME/.sdkman/bin/sdkman-init.sh"
export _JAVA_OPTIONS="-Djava.net.preferIPv4Stack=true"
export GRADLE_OPTS="-Dorg.gradle.daemon=false"
cd /mnt/d/burp-ai-bridge-main/burp-ai-bridge-main/burp-extension
gradle clean build
```

Then load this file into Burp:

```text
D:\burp-ai-bridge-main\burp-ai-bridge-main\burp-extension\build\libs\burp-ai-bridge-0.2.0.jar
```

## Troubleshooting

### Burp cannot reach the API

Check that the FastAPI server is running:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/docs
```

### The server cannot reach Ollama

Check that Ollama is running and the model is present:

```powershell
ollama list
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:11434/api/tags
```

### Burp shows a bridge error

Common causes:

- Uvicorn is not running on `127.0.0.1:8000`
- Ollama is not running on `127.0.0.1:11434`
- `qwen2.5-coder:3b` was not pulled locally
- the Burp tab endpoint field was changed to an invalid URL

### RAG scraping errors

If you use the scraper in `server/rag_engine.py`, ensure the Windows Python environment includes:

```powershell
pip install beautifulsoup4 lxml requests
```

## Security Notes

- This project is designed for advisory analysis of traffic you already captured in Burp.
- It does not automatically run active scanning from the Burp extension.
- Any Nuclei, ffuf, or Nmap usage should be deliberate, scoped, and authorized.
- The operator remains responsible for validation and safe execution.
