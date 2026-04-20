Title: Local Knowledge Base
Source: manual
Tags: kb, instructions

# Local Knowledge Base

Store your local methodology notes here as Markdown files.

Recommended note structure:

## Title
- Short name for the technique or pattern.

## Source
- Original reference URL or book/chapter name.

## Signals
- What request or response traits suggest this check is relevant.

## Validation Approach
- Safe manual verification steps.

## Good Questions
- Operator questions that help confirm or reject the hypothesis.

## Tooling Hints
- Useful nuclei tags
- Useful SecLists wordlists
- Relevant Burp workflow notes

The backend will index all `*.md` files in this directory and retrieve the most relevant chunks during analysis.
