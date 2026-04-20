import os
import re
import json
import math
import requests
from bs4 import BeautifulSoup
from collections import Counter
from pathlib import Path
from typing import List, Dict, Any, Tuple

TOKEN_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_\-]{1,40}")
BASE_DIR = Path(__file__).resolve().parent

def tokenize(text: str) -> List[str]:
    toks = [t.lower() for t in TOKEN_RE.findall(text)]
    stop = {"the", "and", "for", "with", "from", "that", "this", "into", "are", "was", "http", "https"}
    return [t for t in toks if t not in stop and len(t) > 2]

class WebScraper:
    def __init__(self, kb_dir: str | Path | None = None):
        self.kb_dir = BASE_DIR / "kb" if kb_dir is None else Path(kb_dir)
        self.kb_dir.mkdir(parents=True, exist_ok=True)
        # Headers to bypass basic anti-bot protections
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

    def _slugify(self, text: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")

    def scrape_to_kb(self, url: str, topic_name: str) -> str:
        """Scrapes an infosec article and saves it as a markdown note."""
        print(f"[*] Scraping methodology from: {url}")
        try:
            res = requests.get(url, headers=self.headers, timeout=10)
            res.raise_for_status()
            soup = BeautifulSoup(res.text, "lxml")

            # Extract headers, paragraphs, and code blocks
            content = []
            for tag in soup.find_all(['h1', 'h2', 'h3', 'p', 'pre', 'li']):
                text = tag.get_text(separator=" ", strip=True)
                if not text: continue
                
                if tag.name in ['h1', 'h2', 'h3']:
                    content.append(f"\n# {text}\n")
                elif tag.name == 'pre':
                    content.append(f"\n```\n{text}\n```\n")
                elif tag.name == 'li':
                    content.append(f"- {text}")
                else:
                    content.append(text)

            full_text = "\n".join(content)
            
            # Save to kb folder
            safe_name = self._slugify(topic_name)
            file_path = self.kb_dir / f"{safe_name}.md"
            file_path.write_text(f"Source: {url}\n\n{full_text}", encoding="utf-8")
            
            print(f"[+] Saved notes to {file_path}")
            return str(file_path)
        except Exception as e:
            print(f"[-] Failed to scrape {url}: {e}")
            return ""


class KBIndex:
    def __init__(self, kb_dir: str | Path | None = None, rag_dir: str | Path | None = None):
        self.kb_dir = BASE_DIR / "kb" if kb_dir is None else Path(kb_dir)
        self.rag_dir = BASE_DIR / "rag" if rag_dir is None else Path(rag_dir)
        self.index_path = self.rag_dir / "kb_index.json"
        self.chunks = []
        self.idf = {}

    def _chunk_text(self, source: str, text: str, max_words: int = 150) -> List[Dict]:
        words = text.split()
        chunks = []
        start = 0
        idx = 0
        while start < len(words):
            end = min(len(words), start + max_words)
            frag = " ".join(words[start:end]).strip()
            toks = tokenize(frag)
            counts = Counter(toks)
            total = sum(counts.values()) or 1
            tf = {k: v / total for k, v in counts.items()}
            
            chunks.append({
                "chunk_id": f"{source}_{idx}",
                "source": source,
                "text": frag,
                "tf": tf,
                "tokens": toks
            })
            idx += 1
            start += max_words - 30 # overlap
        return chunks

    def build_index(self):
        """Reads all files in kb/ and builds the searchable index."""
        self.rag_dir.mkdir(parents=True, exist_ok=True)
        all_chunks = []
        
        if not self.kb_dir.exists():
            return
            
        for fp in self.kb_dir.rglob("*.md"):
            text = fp.read_text(encoding="utf-8", errors="ignore")
            all_chunks.extend(self._chunk_text(fp.name, text))

        df = Counter()
        for ch in all_chunks:
            for t in set(ch["tokens"]):
                df[t] += 1

        n = max(1, len(all_chunks))
        self.idf = {t: math.log((1 + n) / (1 + d)) + 1.0 for t, d in df.items()}
        self.chunks = all_chunks

        # Save to disk
        serial = {"idf": self.idf, "chunks": self.chunks}
        self.index_path.write_text(json.dumps(serial), encoding="utf-8")
        print(f"[+] KB Index built with {len(all_chunks)} chunks.")

    def load_index(self) -> bool:
        if not self.index_path.exists():
            return False
        data = json.loads(self.index_path.read_text(encoding="utf-8"))
        self.idf = data.get("idf", {})
        self.chunks = data.get("chunks", [])
        return True

    def _scored_chunks(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        if not self.chunks and not self.load_index():
            self.build_index()

        q_toks = tokenize(query)
        if not q_toks:
            return []

        q_counts = Counter(q_toks)
        q_tf = {k: v / sum(q_counts.values()) for k, v in q_counts.items()}

        scored = []
        for ch in self.chunks:
            score = 0.0
            for t, qv in q_tf.items():
                if t in ch["tf"]:
                    score += qv * ch["tf"][t] * self.idf.get(t, 1.0)
            if score > 0:
                scored.append((score, ch))

        scored.sort(key=lambda x: x[0], reverse=True)
        hits = []
        for score, ch in scored[:top_k]:
            hits.append({
                "score": round(score, 6),
                "source": ch["source"],
                "chunk_id": ch["chunk_id"],
                "text": ch["text"],
            })
        return hits

    def search_hits(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        return self._scored_chunks(query, top_k=top_k)

    def search(self, query: str, top_k: int = 3) -> str:
        """Searches the KB and returns formatted text for Qwen."""
        hits = self._scored_chunks(query, top_k=top_k)
        if not hits:
            return "No context found."

        context_blocks = []
        for hit in hits:
            context_blocks.append(f"[Source: {hit['source']}]\n{hit['text']}")
            
        return "\n\n".join(context_blocks)

# Example Usage for testing:
# if __name__ == "__main__":
#     scraper = WebScraper()
#     # Scour HackTricks for IDOR methodology
#     scraper.scrape_to_kb("https://book.hacktricks.xyz/pentesting-web/idor", "hacktricks_idor")
#     
#     idx = KBIndex()
#     idx.build_index()
#     print(idx.search("How to bypass IDOR restrictions?"))
