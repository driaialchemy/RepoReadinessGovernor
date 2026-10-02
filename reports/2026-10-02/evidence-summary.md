# AIAlchemy Repo Governor — Weekly Evidence Report

**Report date:** 2026-10-02T01:49:37+00:00
**GitHub owner:** driaialchemy
**Run mode:** scan_only

## Executive Summary

Repo Governor discovered 13 repositories under driaialchemy. 13 were eligible for scanning. 13 were scanned successfully. 0 were skipped because they were archived, forks, excluded by configuration, or otherwise disabled.
2 passed agent-readiness checks and 11 still need governance work.

Repo Governor scanned 13 repositories under driaialchemy. 2 of 13 scanned repositories are agent-ready. 6 repositories are high-risk and should receive human review before any remediation agent is used. The most common issues are 6 repos with credential pattern indicators and 6 repos with high-risk repos needing controls. The safest next step is to add agent policy files on a medium-risk repo such as AgentAuditLogger using prompt_only mode.

The evidence report was emailed successfully.

## Counts

- Repositories discovered: 13
- Repositories eligible: 13
- Repositories scanned successfully: 13
- Agent-ready (passed): 2
- Need governance work: 11
- High-risk repositories: 6
- Medium-risk repositories: 5
- Low-risk repositories: 2
- Clone failures: 0
- Scan failures: 0
- Unattempted eligible repositories: 0
- Repositories skipped: 0

## Top Portfolio-Wide Issues

- 6 repos: credential pattern indicators
- 6 repos: high-risk repos needing controls
- 5 repos: Medium-risk repo requires governance controls before agent access
- 3 repos: Credential pattern indicators in code: api_key
- 3 repos: Credential pattern indicators in code: api_key, database_url
- 1 repos: Spreadsheet/data export files found: audit_trail.xlsx, audit_trail_with_tools_populated_demo_v2.xlsx, audit_trail_with_tools_populated_demo_v3.xlsx
- 1 repos: Spreadsheet/data export files found: sample_expenses.xlsx
- 1 repos: Spreadsheet/data export files found: synthetic_hidden_equity_data_az (1).xlsx

## Recommended Remediation Order

### Next (medium-risk or missing agent policy files)

- AgentAuditLogger
- EcommerceQueryStudio
- IncomingRequestScreener
- MultiAgentWorkbench
- contract-risk-review-pipeline

### Human review first (high-risk, credentials, AI, databases, CI/CD, containers)

- AgentGovernanceHub
- ContractRiskReview
- EquipmentComplianceTracker
- ExpenseVerificationDesk
- PropertyLeadFinder
- RepoReadinessGovernor

## Per-Repo Action Plans

### driaialchemy/AgentAuditLogger

- **Risk:** MEDIUM
- **Agent-ready:** FAIL
- **Recommended mode:** prompt_only
- **Human review required:** No
- **Top corrective actions:**
  1. Medium-risk repo requires governance controls before agent access
     - Add agent policy files and document verification requirements before agent use.
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (package.json)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
  - Dependency manifests present: package.json
    - Dependency changes should require review and test verification.
  - HTTP networking libraries in use: requests
    - Agent changes should require review for external calls and data handling.
- **Verification steps:**
  - Confirm required governance controls are present for a medium-risk repo.
- **Audit file:** `audit/multi_repo/2026-10-02/repo_AgentAuditLogger_20261002T014938Z.json`

### driaialchemy/AgentGovernanceHub

- **Risk:** HIGH
- **Agent-ready:** FAIL
- **Recommended mode:** human_review_first
- **Human review required:** Yes
- **Top corrective actions:**
  1. Credential pattern indicators found (api_key)
     - Review flagged files to confirm whether actual credentials are present. Replace hardcoded secrets with environment variables or secret manager references.
  2. Credential pattern indicators in code: api_key
     - Review the audit evidence and remediate this blocking issue.
  3. High-risk repo requires additional controls before agent access
     - Document approval gates, sensitive areas, and verification steps before any remediation agent is used.
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (requirements.txt, package.json)
    - Dependency changes should require review and test verification.
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
  - AI provider integrations present (openai)
    - Document API key handling and require human review for provider configuration changes.
  - Database terms present (postgres)
    - Ensure connection strings use environment variables and data handling is documented.
  - External AI API usage: openai — API key management required
    - Review governance implications in the audit evidence before agent use.
- **Verification steps:**
  - Confirm credential pattern indicators are cleared or documented as safe.
  - Re-run scan_only and confirm the issue is resolved.
  - Confirm governance files exist and high-risk blockers are resolved or explicitly approved for human-supervised remediation.
- **Audit file:** `audit/multi_repo/2026-10-02/repo_AgentGovernanceHub_20261002T014939Z.json`

### driaialchemy/ContractRiskReview

- **Risk:** HIGH
- **Agent-ready:** FAIL
- **Recommended mode:** human_review_first
- **Human review required:** Yes
- **Top corrective actions:**
  1. Credential pattern indicators found (api_key)
     - Review flagged files to confirm whether actual credentials are present. Replace hardcoded secrets with environment variables or secret manager references.
  2. Credential pattern indicators in code: api_key
     - Review the audit evidence and remediate this blocking issue.
  3. High-risk repo requires additional controls before agent access
     - Document approval gates, sensitive areas, and verification steps before any remediation agent is used.
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (requirements.txt, pyproject.toml)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
  - CI/CD workflow present
    - Review workflow permissions before allowing agent changes to pipeline files.
  - AI provider integrations present (anthropic, gemini, openai)
    - Document API key handling and require human review for provider configuration changes.
- **Verification steps:**
  - Confirm credential pattern indicators are cleared or documented as safe.
  - Re-run scan_only and confirm the issue is resolved.
  - Confirm governance files exist and high-risk blockers are resolved or explicitly approved for human-supervised remediation.
- **Audit file:** `audit/multi_repo/2026-10-02/repo_ContractRiskReview_20261002T014941Z.json`

### driaialchemy/EcommerceQueryStudio

- **Risk:** MEDIUM
- **Agent-ready:** FAIL
- **Recommended mode:** prompt_only
- **Human review required:** No
- **Top corrective actions:**
  1. Medium-risk repo requires governance controls before agent access
     - Add agent policy files and document verification requirements before agent use.
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (pyproject.toml)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
  - CI/CD workflow present
    - Review workflow permissions before allowing agent changes to pipeline files.
  - Dependency manifests present: pyproject.toml
    - Dependency changes should require review and test verification.
- **Verification steps:**
  - Confirm required governance controls are present for a medium-risk repo.
- **Audit file:** `audit/multi_repo/2026-10-02/repo_EcommerceQueryStudio_20261002T014942Z.json`

### driaialchemy/EquipmentComplianceTracker

- **Risk:** HIGH
- **Agent-ready:** FAIL
- **Recommended mode:** human_review_first
- **Human review required:** Yes
- **Top corrective actions:**
  1. Credential pattern indicators found (api_key, database_url)
     - Review flagged files to confirm whether actual credentials are present. Replace hardcoded secrets with environment variables or secret manager references.
  2. Credential pattern indicators in code: api_key, database_url
     - Review the audit evidence and remediate this blocking issue.
  3. High-risk repo requires additional controls before agent access
     - Document approval gates, sensitive areas, and verification steps before any remediation agent is used.
  4. Spreadsheet/data export files found: audit_trail.xlsx, audit_trail_with_tools_populated_demo_v2.xlsx, audit_trail_with_tools_populated_demo_v3.xlsx
     - Review the audit evidence and remediate this blocking issue.
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
- **Verification steps:**
  - Confirm credential pattern indicators are cleared or documented as safe.
  - Re-run scan_only and confirm the issue is resolved.
  - Confirm governance files exist and high-risk blockers are resolved or explicitly approved for human-supervised remediation.
- **Audit file:** `audit/multi_repo/2026-10-02/repo_EquipmentComplianceTracker_20261002T015004Z.json`

### driaialchemy/ExpenseVerificationDesk

- **Risk:** HIGH
- **Agent-ready:** FAIL
- **Recommended mode:** human_review_first
- **Human review required:** Yes
- **Top corrective actions:**
  1. Credential pattern indicators found (api_key)
     - Review flagged files to confirm whether actual credentials are present. Replace hardcoded secrets with environment variables or secret manager references.
  2. Credential pattern indicators in code: api_key
     - Review the audit evidence and remediate this blocking issue.
  3. High-risk repo requires additional controls before agent access
     - Document approval gates, sensitive areas, and verification steps before any remediation agent is used.
  4. Spreadsheet/data export files found: sample_expenses.xlsx
     - Review the audit evidence and remediate this blocking issue.
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (pyproject.toml)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
  - HTTP networking detected (httpx)
    - Agent changes should require review for external calls and data handling.
  - AI provider integrations present (anthropic)
    - Document API key handling and require human review for provider configuration changes.
  - External AI API usage: anthropic — API key management required
    - Review governance implications in the audit evidence before agent use.
- **Verification steps:**
  - Confirm credential pattern indicators are cleared or documented as safe.
  - Re-run scan_only and confirm the issue is resolved.
  - Confirm governance files exist and high-risk blockers are resolved or explicitly approved for human-supervised remediation.
- **Audit file:** `audit/multi_repo/2026-10-02/repo_ExpenseVerificationDesk_20261002T015005Z.json`

### driaialchemy/IncomingRequestScreener

- **Risk:** MEDIUM
- **Agent-ready:** FAIL
- **Recommended mode:** prompt_only
- **Human review required:** No
- **Top corrective actions:**
  1. Medium-risk repo requires governance controls before agent access
     - Add agent policy files and document verification requirements before agent use.
  2. Missing .gitignore / unintended files may be tracked
     - Add .gitignore entries for .env, virtual environments, caches, local reports, audit temp files, and generated workspaces.
  3. Missing README / project context for agents
     - Add README with repo purpose, setup instructions, test command, expected inputs/outputs, and safe-use notes.
- **Risk signals (context, not automatic defects):**
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
  - HTTP networking libraries in use: requests
    - Agent changes should require review for external calls and data handling.
- **Verification steps:**
  - Confirm required governance controls are present for a medium-risk repo.
  - Re-run scan_only and confirm .gitignore is present.
  - Re-run scan_only and confirm README is present.
- **Audit file:** `audit/multi_repo/2026-10-02/repo_IncomingRequestScreener_20261002T015005Z.json`

### driaialchemy/MultiAgentWorkbench

- **Risk:** MEDIUM
- **Agent-ready:** FAIL
- **Recommended mode:** prompt_only
- **Human review required:** No
- **Top corrective actions:**
  1. Medium-risk repo requires governance controls before agent access
     - Add agent policy files and document verification requirements before agent use.
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (requirements.txt)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
  - Dependency manifests present: requirements.txt
    - Dependency changes should require review and test verification.
  - Test suite present — actively developed project
    - Use the existing test suite as the primary verification mechanism after agent changes.
- **Verification steps:**
  - Confirm required governance controls are present for a medium-risk repo.
- **Audit file:** `audit/multi_repo/2026-10-02/repo_MultiAgentWorkbench_20261002T015006Z.json`

### driaialchemy/PropertyLeadFinder

- **Risk:** HIGH
- **Agent-ready:** FAIL
- **Recommended mode:** human_review_first
- **Human review required:** Yes
- **Top corrective actions:**
  1. Credential pattern indicators found (api_key, database_url)
     - Review flagged files to confirm whether actual credentials are present. Replace hardcoded secrets with environment variables or secret manager references.
  2. Credential pattern indicators in code: api_key, database_url
     - Review the audit evidence and remediate this blocking issue.
  3. High-risk repo requires additional controls before agent access
     - Document approval gates, sensitive areas, and verification steps before any remediation agent is used.
  4. Spreadsheet/data export files found: synthetic_hidden_equity_data_az (1).xlsx
     - Review the audit evidence and remediate this blocking issue.
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (package.json)
    - Dependency changes should require review and test verification.
  - Database terms present (postgres, supabase)
    - Ensure connection strings use environment variables and data handling is documented.
  - Cloud deployment configuration present (wrangler.toml)
    - Deployment changes should require explicit human approval.
  - External database terms detected (postgres, supabase) — potential data compliance risk
    - Review governance implications in the audit evidence before agent use.
  - Cloud deployment configuration present: wrangler.toml
    - Review governance implications in the audit evidence before agent use.
- **Verification steps:**
  - Confirm credential pattern indicators are cleared or documented as safe.
  - Re-run scan_only and confirm the issue is resolved.
  - Confirm governance files exist and high-risk blockers are resolved or explicitly approved for human-supervised remediation.
- **Audit file:** `audit/multi_repo/2026-10-02/repo_PropertyLeadFinder_20261002T015006Z.json`

### driaialchemy/RepoReadinessGovernor

- **Risk:** HIGH
- **Agent-ready:** FAIL
- **Recommended mode:** human_review_first
- **Human review required:** Yes
- **Top corrective actions:**
  1. Credential pattern indicators found (api_key, database_url)
     - Review flagged files to confirm whether actual credentials are present. Replace hardcoded secrets with environment variables or secret manager references.
  2. Credential pattern indicators in code: api_key, database_url
     - Review the audit evidence and remediate this blocking issue.
  3. High-risk repo requires additional controls before agent access
     - Document approval gates, sensitive areas, and verification steps before any remediation agent is used.
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
- **Verification steps:**
  - Confirm credential pattern indicators are cleared or documented as safe.
  - Re-run scan_only and confirm the issue is resolved.
  - Confirm governance files exist and high-risk blockers are resolved or explicitly approved for human-supervised remediation.
- **Audit file:** `audit/multi_repo/2026-10-02/repo_RepoReadinessGovernor_20261002T015007Z.json`

### driaialchemy/contract-risk-review-pipeline

- **Risk:** MEDIUM
- **Agent-ready:** FAIL
- **Recommended mode:** prompt_only
- **Human review required:** No
- **Top corrective actions:**
  1. Medium-risk repo requires governance controls before agent access
     - Add agent policy files and document verification requirements before agent use.
- **Risk signals (context, not automatic defects):**
  - Dependency manifest detected (requirements.txt)
    - Dependency changes should require review and test verification.
  - Test suite detected
    - Use the existing test suite as the primary verification mechanism after agent changes.
  - HTTP networking detected (requests)
    - Agent changes should require review for external calls and data handling.
  - Dependency manifests present: requirements.txt
    - Dependency changes should require review and test verification.
  - HTTP networking libraries in use: requests
    - Agent changes should require review for external calls and data handling.
- **Verification steps:**
  - Confirm required governance controls are present for a medium-risk repo.
- **Audit file:** `audit/multi_repo/2026-10-02/repo_contract-risk-review-pipeline_20261002T014940Z.json`

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
- **Audit file:** `audit/multi_repo/2026-10-02/repo_AgentProposalReview_20261002T014940Z.json`

### driaialchemy/skillsartifactsbuild

- **Risk:** LOW
- **Agent-ready:** PASS
- **Recommended mode:** scan_only
- **Human review required:** No
- **Verification steps:**
  - Re-run weekly evidence in scan_only mode and confirm agent-ready PASS.
- **Audit file:** `audit/multi_repo/2026-10-02/repo_skillsartifactsbuild_20261002T015007Z.json`
