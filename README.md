# \# Titan

# 

# \*\*Evidence-driven, AI-assisted security operations and investigation platform.\*\*

# 

# Titan is an independent cybersecurity engineering project I built to understand how modern security operations systems work end-to-end: from telemetry collection and detection through evidence preservation, AI-assisted triage, analyst workflow, and secure infrastructure.

# 

# The project combines live network and endpoint telemetry with deterministic detections, evidence-backed investigations, controlled AI reasoning, and a browser-based analyst interface.

# 

# > Titan is a portfolio and engineering project, not a production enterprise SIEM or a replacement for platforms such as Splunk or Elasticsearch.

# 

# \---

# 

# \## Why I Built Titan

# 

# I wanted to move beyond studying cybersecurity concepts in isolation and build a system where I could understand how the pieces of a real security operations workflow connect.

# 

# Titan gave me hands-on experience with:

# 

# \- security telemetry collection

# \- endpoint and network monitoring

# \- detection engineering

# \- event normalization

# \- evidence preservation

# \- case management

# \- API security

# \- authentication and RBAC

# \- AI-assisted investigation

# \- AI grounding and failure handling

# \- infrastructure hardening

# \- automated testing and CI

# 

# The goal was not simply to make alerts appear on a dashboard. I wanted to understand how security data moves from a sensor all the way to an analyst decision.

# 

# \---

# 

# \# Architecture

# 

# ```text

# &#x20;                        TITAN SECURITY OPERATIONS

# 

# &#x20; ┌───────────────────────────────────────────────────────────────┐

# &#x20; │                       TELEMETRY SOURCES                       │

# &#x20; │                                                               │

# &#x20; │   Raspberry Pi / Suricata          Windows / Sysmon           │

# &#x20; │      Network telemetry             Endpoint telemetry         │

# &#x20; └───────────────┬───────────────────────────┬───────────────────┘

# &#x20;                 │                           │

# &#x20;                 ▼                           ▼

# &#x20;      ┌───────────────────┐        ┌──────────────────────┐

# &#x20;      │ Suricata eve.json │        │ Winlogbeat / Elastic │

# &#x20;      └─────────┬─────────┘        └──────────┬───────────┘

# &#x20;                │                             │

# &#x20;                ▼                             ▼

# &#x20;      ┌──────────────────────────────────────────────────┐

# &#x20;      │              Titan Sensor Bridges                │

# &#x20;      │                                                  │

# &#x20;      │  Normalization + authenticated machine ingest    │

# &#x20;      └───────────────────────┬──────────────────────────┘

# &#x20;                              │

# &#x20;                              ▼

# &#x20;      ┌──────────────────────────────────────────────────┐

# &#x20;      │             FastAPI Ingestion Gateway            │

# &#x20;      │                                                  │

# &#x20;      │       POST /api/v1/security/ingest/events        │

# &#x20;      └───────────────────────┬──────────────────────────┘

# &#x20;                              │

# &#x20;                              ▼

# &#x20;      ┌──────────────────────────────────────────────────┐

# &#x20;      │             Canonical Security Events            │

# &#x20;      │                                                  │

# &#x20;      │       AuditEvent + normalized metadata           │

# &#x20;      └───────────────────────┬──────────────────────────┘

# &#x20;                              │

# &#x20;                              ▼

# &#x20;      ┌──────────────────────────────────────────────────┐

# &#x20;      │             Deterministic Detection              │

# &#x20;      │                                                  │

# &#x20;      │ Authentication | Network | Endpoint detections   │

# &#x20;      └───────────────────────┬──────────────────────────┘

# &#x20;                              │

# &#x20;                              ▼

# &#x20;      ┌──────────────────────────────────────────────────┐

# &#x20;      │               Security Finding                   │

# &#x20;      │                                                  │

# &#x20;      │      Finding + exact supporting evidence         │

# &#x20;      └───────────────────────┬──────────────────────────┘

# &#x20;                              │

# &#x20;                   ┌──────────┴──────────┐

# &#x20;                   ▼                     ▼

# &#x20;      ┌──────────────────────┐  ┌────────────────────────┐

# &#x20;      │ Deterministic Triage │  │ Claude AI Triage       │

# &#x20;      │                      │  │                        │

# &#x20;      │ Known security facts │  │ Structured reasoning   │

# &#x20;      └──────────┬───────────┘  └───────────┬────────────┘

# &#x20;                 │                          │

# &#x20;                 └────────────┬─────────────┘

# &#x20;                              ▼

# &#x20;      ┌──────────────────────────────────────────────────┐

# &#x20;      │              Titan Grounding Policy              │

# &#x20;      │                                                  │

# &#x20;      │ Evidence > deterministic facts > AI conclusions  │

# &#x20;      └───────────────────────┬──────────────────────────┘

# &#x20;                              │

# &#x20;                              ▼

# &#x20;      ┌──────────────────────────────────────────────────┐

# &#x20;      │               Analyst Case View                  │

# &#x20;      │                                                  │

# &#x20;      │ Evidence | AI history | notes | status | owner   │

# &#x20;      └──────────────────────────────────────────────────┘

# ```

# 

# \---

# 

# \# Security Telemetry

# 

# \## Network

# 

# Titan receives network-security alerts generated by \*\*Suricata\*\* running on a Raspberry Pi sensor.

# 

# The Suricata bridge:

# 

# 1\. reads structured events from `eve.json`

# 2\. extracts relevant alert information

# 3\. converts the event into Titan's normalized sensor format

# 4\. authenticates to Titan using a machine credential

# 5\. sends the event to the ingestion API

# 

# \## Endpoint

# 

# Windows endpoint telemetry is collected using:

# 

# \- Sysmon

# \- Windows Event Logs

# \- Winlogbeat

# \- Elasticsearch

# 

# A dedicated Titan bridge queries Sysmon process-creation telemetry from Elasticsearch and forwards normalized events into Titan.

# 

# The bridge maintains a persistent `search\_after` checkpoint so ingestion can resume after a restart without starting over.

# 

# \---

# 

# \# Detection Engineering

# 

# Titan currently implements deterministic detection rules including:

# 

# | Rule | Detection | MITRE ATT\&CK |

# |---|---|---|

# | AUTH-001 | Repeated authentication failures | T1110 |

# | AUTH-002 | Password spraying across multiple accounts | T1110.003 |

# | AUTH-003 | Successful login following repeated failures | T1110 |

# | NET-001 | Network reconnaissance / scanning | T1046 |

# | ENDPOINT-001 | Suspicious PowerShell execution | T1059.001 |

# 

# Detections create a `SecurityFinding` rather than allowing the AI model to independently decide whether an incident exists.

# 

# Each finding retains references to the exact security events that triggered it.

# 

# \---

# 

# \# Evidence-Driven Investigations

# 

# A core design principle of Titan is:

# 

# > AI can interpret evidence, but it cannot replace evidence.

# 

# Every security finding is tied to the exact underlying telemetry that produced it.

# 

# ```text

# Raw telemetry

# &#x20;     ↓

# Normalized event

# &#x20;     ↓

# Deterministic detection

# &#x20;     ↓

# Security finding

# &#x20;     ↓

# Exact evidence

# &#x20;     ↓

# AI-assisted interpretation

# ```

# 

# This makes investigations explainable and auditable.

# 

# \---

# 

# \# AI-Assisted Triage

# 

# Titan integrates \*\*Anthropic Claude\*\* for structured investigation assistance.

# 

# Before AI analysis occurs, Titan builds a controlled payload containing only approved security evidence and deterministic findings.

# 

# Claude produces structured output including:

# 

# \- executive summary

# \- analyst assessment

# \- confirmed facts

# \- hypotheses

# \- missing context

# \- recommended actions

# \- confidence

# \- compromise status

# 

# Titan then applies a separate grounding policy before presenting the result to the analyst.

# 

# \---

# 

# \# AI Grounding

# 

# Titan deliberately treats the model as a lower-authority reasoning layer.

# 

# The authority hierarchy is:

# 

# ```text

# 1\. Exact security evidence

# 2\. Deterministic Titan analysis

# 3\. Titan grounding policy

# 4\. AI-generated conclusions

# 5\. Human analyst judgment

# ```

# 

# For example, reconnaissance traffic may establish that scanning occurred, but it does \*\*not\*\* establish that the target was compromised.

# 

# Titan can therefore override an AI conclusion when the supplied evidence does not support it.

# 

# \---

# 

# \# AI Reliability

# 

# AI investigations have an explicit lifecycle:

# 

# ```text

# running

# completed

# failed

# ```

# 

# Titan persists the investigation record before contacting the AI provider.

# 

# The AI integration includes:

# 

# \- explicit request timeout

# \- controlled retry behavior

# \- temporary vs permanent provider errors

# \- timeout handling

# \- duplicate-running-run prevention

# \- persistent failure records

# \- nullable output for unsuccessful runs

# \- safe frontend rendering of failed investigations

# 

# A failed AI request therefore does not destroy the investigation record or break the analyst case page.

# 

# \---

# 

# \# Analyst Workflow

# 

# The Titan case interface allows an analyst to:

# 

# \- inspect detection details

# \- view supporting evidence

# \- run AI-assisted triage

# \- review previous AI investigations

# \- view grounding corrections

# \- assign or unassign a case

# \- change investigation status

# \- add analyst notes

# \- review case activity history

# 

# The workflow is designed around the idea that AI assists the analyst rather than autonomously closing incidents.

# 

# \---

# 

# \# Application Security

# 

# \## Authentication

# 

# \- Argon2id password hashing

# \- opaque server-side sessions

# \- session expiration

# \- server-side session revocation

# \- inactive-user enforcement

# 

# \## Authorization

# 

# Role-based access control protects security operations functionality.

# 

# Supported security roles include analyst and administrator access.

# 

# \## CSRF Protection

# 

# State-changing browser requests require a CSRF token tied to the authenticated session.

# 

# Protected operations include:

# 

# \- case updates

# \- analyst notes

# \- assignments

# \- AI triage

# \- logout

# 

# \## Sensor Authentication

# 

# Machine-to-machine sensor ingestion uses a dedicated API credential rather than browser session authentication.

# 

# \---

# 

# \# Infrastructure Hardening

# 

# \## Least-Privilege Elasticsearch Access

# 

# The Sysmon bridge uses a dedicated Elasticsearch reader rather than the `elastic` superuser.

# 

# The service account can read the required Winlogbeat data but cannot perform Elasticsearch administrative operations.

# 

# \## TLS Verification

# 

# The bridge verifies Elasticsearch using its HTTP certificate authority rather than disabling certificate validation.

# 

# \## Non-Root Services

# 

# Both sensor bridges run under a dedicated `titan-sensor` Linux service account instead of `root`.

# 

# ```text

# /opt/titan-sensor       application code

# /etc/titan-sensor.env   protected configuration

# /var/lib/titan-sensor   persistent state/checkpoints

# ```

# 

# \## Restricted Suricata Logs

# 

# Suricata security telemetry is no longer world-readable.

# 

# A dedicated reader group grants Titan only the access necessary to consume `eve.json`.

# 

# \---

# 

# \# Testing

# 

# Titan currently has \*\*63 passing backend tests\*\*.

# 

# Coverage includes:

# 

# \- authentication

# \- sessions

# \- CSRF protection

# \- logout security

# \- sensor authentication

# \- network detections

# \- endpoint detections

# \- AI grounding

# \- AI provider failures

# \- AI investigation lifecycle

# \- duplicate AI-run prevention

# \- failed AI-run serialization

# \- test-environment isolation

# 

# Tests use isolated configuration values rather than loading development secrets.

# 

# The test environment uses an in-memory SQLite database and dummy API credentials.

# 

# \---

# 

# \# Continuous Integration

# 

# GitHub Actions automatically installs the backend in a clean environment and executes the test suite on every push.

# 

# ```text

# Push

# &#x20; ↓

# GitHub Actions

# &#x20; ↓

# Install Python dependencies

# &#x20; ↓

# Run pytest

# &#x20; ↓

# 63 tests

# ```

# 

# The current CI pipeline passes successfully.

# 

# \---

# 

# \# Frontend

# 

# Titan's analyst interface is built with:

# 

# \- Next.js

# \- React

# \- TypeScript

# \- App Router

# \- Tailwind CSS

# 

# A production Next.js build is validated successfully before release.

# 

# \---

# 

# \# Technology Stack

# 

# \## Backend

# 

# \- Python 3.13

# \- FastAPI

# \- Pydantic

# \- SQLAlchemy

# \- PostgreSQL

# \- Alembic

# 

# \## Security / Telemetry

# 

# \- Suricata

# \- Sysmon

# \- Winlogbeat

# \- Elasticsearch

# 

# \## AI

# 

# \- Anthropic Claude

# 

# \## Frontend

# 

# \- Next.js

# \- React

# \- TypeScript

# \- Tailwind CSS

# 

# \## Infrastructure

# 

# \- Raspberry Pi

# \- Linux

# \- systemd

# \- Windows

# \- GitHub Actions

# 

# \---

# 

# \# Repository Structure

# 

# ```text

# Titan/

# ├── backend/

# │   ├── app/

# │   │   ├── core/

# │   │   └── domains/

# │   │       ├── identity/

# │   │       └── security/

# │   ├── alembic/

# │   └── tests/

# │

# ├── frontend/

# │   └── src/

# │       └── app/

# │           └── security/

# │

# └── .github/

# &#x20;   └── workflows/

# ```

# 

# \---

# 

# \# Known Limitations

# 

# Titan is an engineering and portfolio project rather than a production enterprise SOC.

# 

# Current limitations include:

# 

# \- lab-scale deployment

# \- limited number of telemetry sources

# \- limited detection catalog

# \- single-node development architecture

# \- sensor credentials are managed locally rather than through an enterprise secrets platform

# \- no distributed rate-limit store

# \- no high-availability deployment

# \- no large-scale event-processing pipeline

# 

# These limitations are intentional boundaries rather than claims of enterprise-scale readiness.

# 

# \---

# 

# \# Future Direction

# 

# Titan Security Operations is part of a broader project exploring privacy-first organizational intelligence.

# 

# The long-term Titan vision is to transform approved organizational information into explainable, evidence-backed decision support while preserving strong security, provenance, and human oversight.

# 

# The security platform developed here provides the technical foundation for protecting that future system.

# 

# \---

# 

# \# What I Learned

# 

# Building Titan gave me practical experience connecting security concepts that are often learned separately.

# 

# I had to reason about:

# 

# \- where telemetry originates

# \- how it moves across systems

# \- how detections should be structured

# \- how evidence should be preserved

# \- what AI should and should not be allowed to conclude

# \- how analyst workflows interact with backend state

# \- how authentication and authorization affect security tooling

# \- how services should operate under least privilege

# \- how failures should be persisted and recovered

# \- how tests and CI protect changes over time

# 

# The biggest lesson was that a security platform is not simply a collection of alerts.

# 

# It is a chain of trust from:

# 

# ```text

# telemetry

# → evidence

# → detection

# → investigation

# → reasoning

# → human decision

# ```

