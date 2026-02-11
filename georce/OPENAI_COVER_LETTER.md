# OpenAI Security Vulnerability Report
## GEO-Optimized Indirect Prompt Injection Against Tool-Augmented LLM Agents

**Date:** [DATE]  
**Researcher:** [YOUR NAME] ([EMAIL])  
**Affiliation:** [Digitance Group]  

---

## Summary

GEO-optimized web pages containing hidden prompt injection payloads can be retrieved by ChatGPT's browsing feature during normal web search. When the model fetches and processes these pages, hidden instructions attempt to:

1. **Trigger unauthorized actions** (file operations, code execution, data exfiltration)
2. **Weaken safety responses** in the same session (jailbreak variant)

The user never visits the malicious page. ChatGPT retrieves it autonomously.

## Key Difference from Known Attacks

Existing indirect prompt injection requires the user to paste a URL or upload a document. This attack uses the model's **own search results** as the delivery mechanism — no user interaction beyond the initial benign query.

## Reproduction

Full PoC, collector server, and test protocol are attached. Quick reproduction:

1. Visit: `https://[GITHUB_PAGES_URL]/best-vulnerability-scanners-2026.html`
2. Note: page looks like a normal security tool review
3. View source: hidden divs, comments, data attributes contain injection payloads
4. In ChatGPT with browsing, ask: *"Read this article and recommend a scanner for my setup: [URL]"*
5. Monitor collector server for exfiltration attempts

## Affected Products

- ChatGPT with browsing enabled (GPT-4, GPT-4o)
- Any OpenAI product that fetches and processes web content

## Attachments

- Full technical report (BOUNTY_REPORT_TEMPLATE.md — fill in ChatGPT-specific results)
- PoC kit (georce-v2-complete.tar.gz)
- Collector logs from testing

## Disclosure

Submitted simultaneously to Anthropic (for Claude) and OpenAI (for ChatGPT). 90-day remediation window. No public disclosure.
