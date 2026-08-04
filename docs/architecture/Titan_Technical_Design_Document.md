# Titan Intelligence — Technical Design Document

**Document status:** Draft v0.1  
**Product:** Titan Executive  
**Owner:** Titan Intelligence  
**Current phase:** Season 1 — Secure SaaS Foundation  
**Last updated:** August 4, 2026

---

## 1. Purpose

This document defines the initial technical architecture for Titan Executive and the internal security capability that will protect it.

Titan Executive is the first customer-facing product of Titan Intelligence. It will transform approved organizational information into prioritized, explainable executive briefings.

The internal AI-assisted SOC will monitor Titan’s application, identity, infrastructure, and security telemetry. Its purpose is to protect Titan while providing a real operating environment for detection engineering, alert triage, incident investigation, automation, and security observability.

This document is intentionally limited to the first six months. It does not attempt to design Titan’s entire long-term platform.

---

## 2. Product Definition

### 2.1 Customer problem

Executives receive information from many disconnected sources but lack a reliable system that identifies:

- What requires attention now
- Why it matters
- What evidence supports the conclusion
- What action should be considered next

### 2.2 Initial product promise

Titan Executive will allow an authorized executive to:

1. Create and secure an account.
2. Upload approved business documents.
3. Receive a short executive briefing.
4. Review the evidence supporting each priority.
5. Ask follow-up questions about the uploaded information.
6. Maintain control over what data Titan can access.

### 2.3 MVP scope

The first launch will support:

- Secure user authentication
- Organization-scoped accounts
- Manual document upload
- PDF, text, CSV, and selected office-document ingestion
- Three to five prioritized briefing items
- Source citations
- Basic conversational follow-up
- Audit logging
- Security monitoring
- A deployed production environment

### 2.4 Explicitly out of scope for the MVP

- Autonomous business decisions
- AI departments
- Broad ERP or CRM replacement
- Full Microsoft 365 tenant access
- Full company-database access
- Customer-facing Titan Security product
- Hardware appliances
- Mobile applications
- Multi-agent orchestration
- Kubernetes unless operational need justifies it

---

## 3. System Context

Titan Intelligence consists of two related systems.

### 3.1 Titan Executive

The customer-facing SaaS application.

Responsibilities:

- Identity and access
- Organization workspaces
- Document ingestion
- Briefing generation
- Evidence display
- Executive interaction
- Data controls

### 3.2 Titan Security Operations

The internal security capability protecting Titan.

Responsibilities:

- Collect application and infrastructure telemetry
- Monitor authentication activity
- Detect suspicious behavior
- Triage security alerts
- Support investigations
- Preserve evidence
- Improve detections over time

Titan Security Operations is not an MVP customer product. It is an internal operational capability.

---

## 4. High-Level Architecture

```text
Executive Browser
        |
        | HTTPS
        v
Next.js Frontend
        |
        | Authenticated API requests
        v
FastAPI Backend
        |
        +--------------------+
        |                    |
        v                    v
PostgreSQL             Object Storage
        |                    |
        +---------+----------+
                  |
                  v
        Document Processing
                  |
                  v
       Retrieval / AI Pipeline
                  |
                  v
        Executive Briefing

All major components
        |
        v
Structured Security Logs
        |
        v
Titan Security Operations
        |
        v
Elastic / Detection / AI Triage
```

---

## 5. Technology Stack

### 5.1 Frontend

- Next.js
- TypeScript
- React
- Tailwind CSS
- Server-side rendering where useful
- Secure browser cookies for authentication state

### 5.2 Backend

- FastAPI
- Python
- Pydantic
- SQLAlchemy
- Alembic
- REST API
- Background jobs added only when required

### 5.3 Data

- PostgreSQL for relational application data
- Encrypted object storage for uploaded documents
- Vector search introduced only when document retrieval requires it
- Redis considered later for rate limiting, caching, or job queues

### 5.4 Security Operations

- Elastic Security and Kibana
- Existing AI triage engine
- Structured application logs
- Infrastructure and authentication telemetry
- MITRE ATT&CK mapping where applicable

### 5.5 Deployment

Initial deployment should favor simplicity:

- Containerized frontend and backend
- Managed PostgreSQL
- Managed object storage
- HTTPS
- Centralized secrets
- Separate development and production environments

The exact cloud provider remains an implementation decision and should be documented through an Architecture Decision Record.

---

## 6. Repository Structure

Initial monorepo structure:

```text
Titan/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── db/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── security/
│   │   └── main.py
│   ├── tests/
│   ├── alembic/
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   ├── components/
│   │   ├── features/
│   │   ├── lib/
│   │   └── types/
│   ├── public/
│   └── .env.example
├── security/
│   ├── detections/
│   ├── dashboards/
│   ├── playbooks/
│   ├── simulations/
│   └── ai-triage/
├── docs/
│   ├── architecture/
│   ├── decisions/
│   ├── security/
│   ├── operations/
│   └── product/
├── infrastructure/
├── scripts/
├── .github/
└── README.md
```

The existing repository should be migrated carefully rather than rewritten unnecessarily.

---

## 7. Identity and Authentication

Authentication is the first major production feature because it creates both customer value and meaningful security telemetry.

### 7.1 Initial capabilities

- User registration
- Email verification
- Secure login
- Password reset
- MFA enrollment
- MFA verification
- Logout
- Session revocation
- Account disablement
- Organization membership
- Role-based authorization

### 7.2 Password security

- Use a modern adaptive password-hashing algorithm.
- Never store plaintext passwords.
- Enforce reasonable password length.
- Avoid arbitrary complexity rules that encourage predictable behavior.
- Prevent credentials from appearing in logs.
- Use single-use, expiring reset tokens.

### 7.3 Session design

Preferred initial approach:

- Server-managed sessions
- Random opaque session identifiers
- Session identifier stored in a Secure, HttpOnly, SameSite cookie
- Session records stored server-side
- Idle expiration
- Absolute expiration
- Rotation after login, MFA, password change, and privilege change
- Ability to revoke individual or all sessions

This approach is preferred over exposing long-lived JWTs to browser JavaScript.

### 7.4 MFA

Initial MFA method:

- TOTP authenticator application
- One-time recovery codes
- Recovery codes hashed at rest
- MFA required for privileged roles
- MFA events recorded in the audit trail

SMS should not be the primary MFA method.

### 7.5 Authorization

Initial roles:

- `owner`
- `admin`
- `executive`
- `member`
- `security_auditor`

Authorization must be enforced by the backend, not only hidden in the frontend.

Every organization-scoped query must validate both:

- The authenticated user
- The organization the user is authorized to access

---

## 8. Security Controls

### 8.1 Core principles

- Least privilege
- Deny by default
- Defense in depth
- Secure defaults
- Customer-controlled data access
- Traceability
- Human approval for consequential actions

### 8.2 Initial controls

- HTTPS everywhere
- Secure cookie attributes
- CSRF protection
- Rate limiting
- Input validation
- Output encoding
- File-size and file-type restrictions
- Malware scanning for uploaded files
- Secrets outside source control
- Database encryption in transit
- Storage encryption at rest
- Dependency scanning
- Security headers
- Generic authentication error messages
- Administrative action logging

### 8.3 File upload security

Uploaded documents are a major attack surface.

The ingestion pipeline must:

1. Validate extension and detected content type.
2. Reject unsupported formats.
3. Enforce upload-size limits.
4. Rename files using internal identifiers.
5. Store files outside the web root.
6. Scan files before processing.
7. Process files in an isolated worker.
8. Treat document content as untrusted input.
9. Defend against prompt injection in uploaded documents.
10. Preserve provenance from each extracted statement back to its source.

---

## 9. Audit Logging

Audit logs provide accountability and feed the internal SOC.

### 9.1 Audit events

The system should record:

- Registration
- Email verification
- Successful login
- Failed login
- MFA challenge and result
- Password reset
- Password change
- Session creation
- Session revocation
- Role change
- User invitation
- User removal
- Document upload
- Document deletion
- Briefing generation
- Sensitive-data access
- Administrative configuration changes

### 9.2 Required audit fields

```text
event_id
timestamp_utc
event_type
actor_user_id
organization_id
target_type
target_id
request_id
session_id_hash
source_ip
user_agent
result
failure_reason_code
risk_metadata
```

Sensitive secrets, raw passwords, tokens, and unnecessary document content must never be logged.

### 9.3 Audit integrity

- Append-oriented design
- Restricted write permissions
- Restricted read permissions
- Retention policy
- Time synchronization
- Export to the security monitoring platform
- Alerts for logging interruption or tampering indicators

---

## 10. Application Logging and Observability

Three distinct log categories should remain separate.

### 10.1 Application logs

Used to diagnose application behavior.

Examples:

- Service startup
- Request failures
- Dependency failures
- Document-processing status

### 10.2 Audit logs

Used to record security-relevant and business-relevant actions.

### 10.3 Security events

Derived events designed for detection.

Examples:

- Repeated authentication failures
- MFA failures
- Login after password reset
- Privileged-role assignment
- Session revocation anomaly
- Large or unusual document upload
- Access-denied spikes

### 10.4 Structured format

Logs should be emitted as structured JSON with:

- UTC timestamp
- Severity
- Service
- Environment
- Event name
- Request ID
- Correlation ID
- Sanitized metadata

---

## 11. Initial Detection Engineering Use Cases

The first detections should map directly to Titan’s real attack surface.

### 11.1 Authentication detections

- Multiple failed logins for one account
- Multiple failed logins from one source
- Password spraying pattern
- Successful login after repeated failures
- Repeated MFA failures
- Login from a previously unseen device
- Privileged account login anomaly
- Disabled-account authentication attempt

### 11.2 Session detections

- Session use after revocation
- Concurrent geographically inconsistent session activity
- Sudden session churn
- Privilege change followed by sensitive access
- Suspicious user-agent changes within one session

### 11.3 API detections

- Rate-limit violations
- Repeated authorization failures
- Enumeration behavior
- Unusual API request volume
- Access attempts across organization boundaries
- Unexpected administrative endpoint access

### 11.4 File and AI pipeline detections

- Unsupported-file upload attempts
- Repeated malware-scan failures
- Excessive upload volume
- Prompt-injection indicators
- Unusual document-access patterns
- Briefing generation from unauthorized sources

---

## 12. AI SOC Integration

### 12.1 Data flow

```text
Titan Application
      |
Structured logs and audit events
      |
Log transport
      |
Elastic Security
      |
Detection rules
      |
Security alerts
      |
AI triage engine
      |
Analyst review / incident case
```

### 12.2 AI role

The AI triage system may:

- Summarize alerts
- Correlate related events
- Assign a provisional severity
- Map activity to MITRE ATT&CK
- Explain supporting evidence
- Recommend investigation steps
- Produce a case summary

The AI must not:

- Suppress critical alerts without review
- Permanently block users without an approved policy
- Claim certainty unsupported by evidence
- modify production data autonomously

### 12.3 Human-in-the-loop

Security decisions with material impact require human approval.

Examples:

- Disabling an account
- Revoking all user sessions
- Blocking an IP globally
- Deleting uploaded data
- Declaring a confirmed incident

---

## 13. Executive Intelligence Pipeline

### 13.1 Ingestion

- Accept authorized documents.
- Validate and scan files.
- Extract text and structure.
- Preserve source metadata.
- Assign the document to an organization.

### 13.2 Understanding

Classify the document by:

- Type
- Date
- Department or domain
- People
- Projects
- Deadlines
- Risks
- Commitments
- Financial or operational impact

### 13.3 Correlation

Identify relationships across documents:

- Shared entities
- Conflicting statements
- Repeated issues
- Approaching deadlines
- Changes from previous reports
- Dependencies between events

### 13.4 Prioritization

Every candidate briefing item should be evaluated using explicit factors:

- Business impact
- Urgency
- Confidence
- Executive relevance
- Deadline proximity
- Number and quality of supporting sources
- Strategic-goal alignment
- Novelty or meaningful change
- Potential downside if ignored

The initial engine may combine deterministic rules with model-assisted classification. It must not rely on an unexplained model score alone.

### 13.5 Explanation

Every briefing item must include:

- What happened
- Why it matters
- Why it was prioritized
- Confidence or uncertainty
- Supporting sources
- Recommended next action
- Clear separation between fact, inference, and recommendation

---

## 14. Data Model — Initial Entities

Initial relational entities:

- `users`
- `organizations`
- `organization_memberships`
- `roles`
- `sessions`
- `mfa_methods`
- `recovery_codes`
- `email_verification_tokens`
- `password_reset_tokens`
- `documents`
- `document_chunks`
- `briefings`
- `briefing_items`
- `source_links`
- `audit_events`
- `security_events`

Detailed schemas will be defined before implementation through database migrations.

---

## 15. API Design

Initial API namespace:

```text
/api/v1/
```

Initial endpoint groups:

```text
/api/v1/health
/api/v1/auth
/api/v1/users
/api/v1/organizations
/api/v1/sessions
/api/v1/documents
/api/v1/briefings
/api/v1/audit
```

API requirements:

- Pydantic validation
- Consistent error format
- Request IDs
- Authorization checks
- Rate limiting
- OpenAPI documentation
- Security-sensitive responses that do not leak internal detail

---

## 16. Environment and Configuration

Required environments:

- Local development
- Test
- Production

Configuration rules:

- No secrets committed to Git
- `.env.example` contains names, never real values
- Production secrets stored in a managed secret store
- Environment-specific settings validated on startup
- Application refuses to start when critical secure settings are missing
- Debug mode disabled in production
- Allowed origins explicitly configured

---

## 17. Testing Strategy

### 17.1 Backend

- Unit tests for business logic
- API integration tests
- Authentication tests
- Authorization-boundary tests
- Organization-isolation tests
- Audit-event tests
- File-validation tests

### 17.2 Frontend

- Component tests
- Authentication-flow tests
- Error-state tests
- Accessibility checks

### 17.3 Security

- Dependency scanning
- Static analysis
- Secret scanning
- Authentication abuse tests
- Rate-limit tests
- IDOR and cross-tenant-access tests
- Upload security tests
- Log-integrity tests

### 17.4 AI

- Grounding tests
- Source-citation tests
- Prompt-injection tests
- Hallucination and unsupported-claim tests
- Prioritization evaluation against human-reviewed scenarios

---

## 18. Deployment and Operations

The first production deployment must include:

- HTTPS
- Health checks
- Database backups
- Centralized logs
- Error monitoring
- Uptime monitoring
- Versioned releases
- Rollback procedure
- Minimal incident-response playbook
- Separate production credentials
- Restricted administrative access

A “production environment” means an intentionally operated live system. It does not imply enterprise scale or replace professional work experience.

---

## 19. Six-Month Milestones

### Month 1 — Foundation

- Repository restructuring
- Configuration
- Structured logging
- Database foundation
- Architecture documentation
- Initial tests

### Month 2 — Identity

- Registration
- Login
- Password reset
- Email verification
- Sessions
- MFA
- RBAC
- Audit logging

### Month 3 — Deployment and Security Operations

- Production deployment
- HTTPS
- Centralized telemetry
- Initial Titan-specific detections
- AI SOC ingestion
- Incident-response playbooks

### Month 4 — Document Intelligence

- Secure uploads
- Parsing
- Source tracking
- Initial retrieval pipeline
- Prompt-injection defenses

### Month 5 — Executive Briefing

- Priority-item generation
- Evidence
- Follow-up questions
- Human-reviewed evaluation
- Usability refinement

### Month 6 — Controlled Pilot

- Limited pilot users
- Security review
- Feedback collection
- Reliability fixes
- Measured executive value
- First paid pilot if justified

---

## 20. Career Evidence Produced

Each major component should create demonstrable evidence for cybersecurity interviews.

Examples:

- Authentication architecture
- MFA implementation
- Secure session management
- RBAC and tenant isolation
- Structured audit logging
- Brute-force and password-spray detections
- API-abuse detections
- Cloud and application telemetry
- AI-assisted alert triage
- Incident investigation
- Security architecture documentation
- Threat modeling
- Secure deployment and secrets management

Claims must remain precise and honest:

> Designed, deployed, and operated the security capability for a live SaaS application developed as an independent startup project.

Do not imply unsupported enterprise scale, customer volume, or employment history.

---

## 21. Definition of Success

At the end of the first six months, Titan succeeds if:

1. Titan Executive is deployed and usable.
2. Authentication and organization isolation are secure and tested.
3. Uploaded data produces grounded executive briefings.
4. Every insight points to supporting evidence.
5. The internal SOC monitors real Titan telemetry.
6. Security detections produce explainable alerts.
7. At least a small number of pilot users provide meaningful feedback.
8. The work produces strong, truthful cybersecurity interview demonstrations.
9. The team knows what to build next based on evidence rather than speculation.

---

## 22. Immediate Next Tasks

1. Confirm and migrate the repository into the target structure.
2. Create `backend/app/main.py`.
3. Add environment-based settings validation.
4. Add a versioned health endpoint.
5. Implement structured JSON logging.
6. Define the first Architecture Decision Records.
7. Design the authentication and session database schema.
8. Define the audit-event schema.
9. Commit the technical design document.
10. Open Sprint 1 issues in GitHub.

---

## 23. Architecture Decision Records to Create

- ADR-001: Monorepo and modular-monolith structure
- ADR-002: FastAPI backend
- ADR-003: Next.js frontend
- ADR-004: PostgreSQL primary database
- ADR-005: Server-managed browser sessions
- ADR-006: TOTP as initial MFA method
- ADR-007: Structured JSON audit and application logging
- ADR-008: Elastic Security for internal monitoring
- ADR-009: Manual document upload as the initial ingestion method
- ADR-010: Human approval for consequential security and executive actions
