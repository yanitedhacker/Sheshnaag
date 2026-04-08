# Sheshnaag Knowledge System

## Goal

Sheshnaag needs a knowledge system that preserves:

- raw source truth
- reusable analyst context
- durable implementation and product decisions
- provenance-friendly summaries for future runs and reports

## Approach

The repo should pair two layers:

### 1. Raw Sources

- keep original advisories, feed payloads, notes, and references intact
- store hashes and provenance metadata where possible
- avoid losing source fidelity during summarization

### 2. LLM Wiki Layer

Following the spirit of the Karpathy LLM wiki pattern, maintain structured human-readable summaries that are:

- derived from raw source material
- easy for humans and agents to extend
- linked back to underlying sources
- stable enough to support repeated planning and implementation work

## MemPalace Role

MemPalace is the long-lived operational memory layer for:

- decisions and tradeoffs
- unfinished implementation threads
- roadmap continuity
- cross-session context for the Sheshnaag buildout

## Recommended Structure

- raw source drawers or files for advisories and references
- wiki pages for product, architecture, safety, and validation patterns
- project memories for decisions, constraints, and unresolved risks

## Usage Principle

Never let the summary layer replace the raw source layer. The point is not just recall; it is defensible, attributable recall.
