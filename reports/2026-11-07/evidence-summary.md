# AIAlchemy Repo Governor — Weekly Evidence Report

**Report date:** 2026-11-07T02:40:35+00:00
**GitHub owner:** driaialchemy
**Run mode:** scan_only

## Executive Summary

Repo Governor discovered 13 repositories under driaialchemy. 13 were eligible for scanning. 13 were scanned successfully. 0 were skipped because they were archived, forks, excluded by configuration, or otherwise disabled.
13 passed agent-readiness checks and 0 still need governance work.

Repo Governor scanned 13 repositories under driaialchemy. All scanned repositories are currently agent-ready.  Review high-risk repositories with human oversight before remediation.

The evidence report was emailed successfully.

## Counts

- Repositories discovered: 13
- Repositories eligible: 13
- Repositories scanned successfully: 13
- Agent-ready (passed): 13
- Need governance work: 0
- High-risk repositories: 0
- Medium-risk repositories: 0
- Low-risk repositories: 13
- Clone failures: 0
- Scan failures: 0
- Unattempted eligible repositories: 0
- Repositories skipped: 0

## Per-Repo Action Plans

### driaialchemy/AgentAuditLogger

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (package.json)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_AgentAuditLogger_20261107T024036Z.json`

### driaialchemy/AgentGovernanceHub

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (requirements.txt, package.json)
    - Dependency changes should require review and test verification.
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
  - AI provider integrations present (openai)
    - Document API key handling and require human review for provider configuration changes.
  - Database terms present (postgres)
    - Ensure connection strings use environment variables and data handling is documented.
- **Accepted risks (reviewed exceptions):**
  - AI provider usage (openai) — accepted: OpenAI is the product's intended LLM integration; keys come from environment variables (approved by Dr. Michael Seller on 2026-11-06)
  - External database use (postgres) — accepted: Postgres is the application's intended datastore; connection strings come from environment variables (approved by Dr. Michael Seller on 2026-11-06)
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_AgentGovernanceHub_20261107T024037Z.json`

### driaialchemy/AgentProposalReview

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_AgentProposalReview_20261107T024038Z.json`

### driaialchemy/ContractRiskReview

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (requirements.txt)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
  - CI/CD workflow present
    - Review workflow permissions before allowing agent changes to pipeline files.
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_ContractRiskReview_20261107T024039Z.json`

### driaialchemy/EcommerceQueryStudio

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (pyproject.toml)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
  - CI/CD workflow present
    - Review workflow permissions before allowing agent changes to pipeline files.
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_EcommerceQueryStudio_20261107T024039Z.json`

### driaialchemy/ElevateBranson

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (package.json)
    - Dependency changes should require review and test verification.
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
  - AI provider integrations present (openai)
    - Document API key handling and require human review for provider configuration changes.
- **Accepted risks (reviewed exceptions):**
  - AI provider usage (openai) — accepted: OpenAI is the product's intended LLM integration; keys come from environment variables (approved by Dr. Michael Seller on 2026-11-06)
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_ElevateBranson_20261107T024040Z.json`

### driaialchemy/EquipmentComplianceTracker

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (requirements.txt)
    - Dependency changes should require review and test verification.
  - HTTP networking detected (httpx, requests)
    - Agent changes should require review for external calls and data handling.
  - Container configuration present
    - Restrict agent access to container build and deployment commands.
  - AI provider integrations present (anthropic, gemini, google.generativeai, openai)
    - Document API key handling and require human review for provider configuration changes.
  - Database terms present (postgres)
    - Ensure connection strings use environment variables and data handling is documented.
- **Accepted risks (reviewed exceptions):**
  - Spreadsheet/data export files found: sample_data/audit_trail.xlsx, sample_data/audit_trail_with_tools_populated_demo_v2.xlsx, sample_data/audit_trail_with_tools_populated_demo_v3.xlsx — accepted: Demo workbooks in sample_data/ and the seed catalog in seed/ (needed by container config); no real operational data (approved by Dr. Michael Seller on 2026-11-06)
  - AI provider usage (anthropic, gemini, google.generativeai, openai) — accepted: Multi-model compliance agents are the product's purpose; keys come from environment variables (approved by Dr. Michael Seller on 2026-11-06)
  - External database use (postgres) — accepted: Optional PostgreSQL backend; connection comes from DATABASE_URL in .env (gitignored) (approved by Dr. Michael Seller on 2026-11-06)
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_EquipmentComplianceTracker_20261107T024057Z.json`

### driaialchemy/ExpenseVerificationDesk

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (pyproject.toml)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
  - HTTP networking detected (httpx)
    - Agent changes should require review for external calls and data handling.
  - AI provider integrations present (anthropic)
    - Document API key handling and require human review for provider configuration changes.
- **Accepted risks (reviewed exceptions):**
  - Spreadsheet/data export files found: sample_data/sample_expenses.xlsx — accepted: Synthetic expense fixture (40 rows) used by the README and tests; no real expense data (approved by Dr. Michael Seller on 2026-11-06)
  - AI provider usage (anthropic) — accepted: Anthropic is the intended LLM for expense checking; keys come from environment variables (approved by Dr. Michael Seller on 2026-11-06)
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_ExpenseVerificationDesk_20261107T024058Z.json`

### driaialchemy/IncomingRequestScreener

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_IncomingRequestScreener_20261107T024058Z.json`

### driaialchemy/MultiAgentWorkbench

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (requirements.txt)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_MultiAgentWorkbench_20261107T024059Z.json`

### driaialchemy/PropertyLeadFinder

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (package.json)
    - Dependency changes should require review and test verification.
  - Database terms present (postgres, supabase)
    - Ensure connection strings use environment variables and data handling is documented.
  - Cloud deployment configuration present (wrangler.toml)
    - Deployment changes should require explicit human approval.
- **Accepted risks (reviewed exceptions):**
  - Spreadsheet/data export files found: sample_data/synthetic_hidden_equity_data_az.xlsx — accepted: Synthetic generated sample workbook (Faker contacts); must never be replaced with real prospect data (approved by Dr. Michael Seller on 2026-11-06)
  - External database use (postgres, supabase) — accepted: Supabase/Postgres is the application's intended datastore; connection details come from environment variables (approved by Dr. Michael Seller on 2026-11-06)
  - Cloud deployment configuration (wrangler.toml) — accepted: Cloudflare Workers deploy config; deployment changes still require explicit human approval (see AGENTS.md) (approved by Dr. Michael Seller on 2026-11-06)
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_PropertyLeadFinder_20261107T024100Z.json`

### driaialchemy/RepoReadinessGovernor

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (pyproject.toml)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
  - HTTP networking detected (aiohttp, httpx, requests)
    - Agent changes should require review for external calls and data handling.
  - CI/CD workflow present
    - Review workflow permissions before allowing agent changes to pipeline files.
  - AI provider integrations present (anthropic, gemini, google.generativeai, openai)
    - Document API key handling and require human review for provider configuration changes.
- **Accepted risks (reviewed exceptions):**
  - AI provider usage (anthropic, gemini, google.generativeai, openai) — accepted: Provider names appear as detection terms in scanner/classifier source, tests and docs; the tool makes no provider calls (approved by Dr. Michael Seller on 2026-11-06)
  - External database use (postgres, supabase) — accepted: Database names appear as detection terms in scanner/classifier source, tests and docs; the tool uses no database (approved by Dr. Michael Seller on 2026-11-06)
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_RepoReadinessGovernor_20261107T024101Z.json`

### driaialchemy/contract-risk-review-pipeline

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (requirements.txt)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-11-07/repo_contract-risk-review-pipeline_20261107T024038Z.json`
