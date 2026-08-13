import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the GitLab namespace/project path, for example group/project
SOURCE_REPO = "anthropics/claude-code"
# todo: the name of the repository
REPO_NAME = "claude-code"

run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index"""
    return (int(run_number) - 1) % max_index + 1


def load_repository_urls():
    """Load repository URLs from repositories.json."""
    repo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repositories.json")
    if not os.path.exists(repo_file):
        return []

    try:
        with open(repo_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    return [url for url in data if isinstance(url, str) and url.strip()]


if run_number == "0":
    BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
    repository_urls = load_repository_urls()
    if repository_urls:
        run_index = get_cyclic_index(run_number, len(repository_urls))
        BASE_URL = repository_urls[run_index - 1]
    else:
        BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"

scope_files = [
    # =================================================================================
    # Core automation entrypoints and issue/PR mutation flows
    # =================================================================================
    "scripts/auto-close-duplicates.ts",
    "scripts/backfill-duplicate-comments.ts",
    "scripts/comment-on-duplicates.sh",
    "scripts/edit-issue-labels.sh",
    "scripts/gh.sh",
    "scripts/issue-lifecycle.ts",
    "scripts/lifecycle-comment.ts",
    "scripts/sweep.ts",

    # =================================================================================
    # Built-in top-level commands shipped with the repo
    # =================================================================================
    ".claude/commands/commit-push-pr.md",
    ".claude/commands/dedupe.md",
    ".claude/commands/triage-issue.md",

    # =================================================================================
    # Hookify: untrusted rule parsing, hook dispatch, and decision enforcement
    # =================================================================================
    "plugins/hookify/agents/conversation-analyzer.md",
    "plugins/hookify/commands/configure.md",
    "plugins/hookify/commands/help.md",
    "plugins/hookify/commands/hookify.md",
    "plugins/hookify/commands/list.md",
    "plugins/hookify/core/config_loader.py",
    "plugins/hookify/core/rule_engine.py",
    "plugins/hookify/hooks/posttooluse.py",
    "plugins/hookify/hooks/pretooluse.py",
    "plugins/hookify/hooks/stop.py",
    "plugins/hookify/hooks/userpromptsubmit.py",
    "plugins/hookify/skills/writing-rules/SKILL.md",

    # =================================================================================
    # Security-guidance: diff capture, repo reads, external review calls, and findings enforcement
    # =================================================================================
    "plugins/security-guidance/hooks/_base.py",
    "plugins/security-guidance/hooks/diffstate.py",
    "plugins/security-guidance/hooks/ensure_agent_sdk.py",
    "plugins/security-guidance/hooks/extensibility.py",
    "plugins/security-guidance/hooks/gitutil.py",
    "plugins/security-guidance/hooks/llm.py",
    "plugins/security-guidance/hooks/patterns.py",
    "plugins/security-guidance/hooks/review_api.py",
    "plugins/security-guidance/hooks/security_reminder_hook.py",
    "plugins/security-guidance/hooks/session_state.py",
    "plugins/security-guidance/hooks/sg-python.sh",

    # =================================================================================
    # Command packs that can steer tool use, git actions, or file mutations
    # =================================================================================
    "plugins/agent-sdk-dev/agents/agent-sdk-verifier-py.md",
    "plugins/agent-sdk-dev/agents/agent-sdk-verifier-ts.md",
    "plugins/agent-sdk-dev/commands/new-sdk-app.md",
    "plugins/code-review/commands/code-review.md",
    "plugins/commit-commands/commands/clean_gone.md",
    "plugins/commit-commands/commands/commit-push-pr.md",
    "plugins/commit-commands/commands/commit.md",
    "plugins/feature-dev/agents/code-architect.md",
    "plugins/feature-dev/agents/code-explorer.md",
    "plugins/feature-dev/agents/code-reviewer.md",
    "plugins/feature-dev/commands/feature-dev.md",
    "plugins/pr-review-toolkit/agents/code-reviewer.md",
    "plugins/pr-review-toolkit/agents/code-simplifier.md",
    "plugins/pr-review-toolkit/agents/comment-analyzer.md",
    "plugins/pr-review-toolkit/agents/pr-test-analyzer.md",
    "plugins/pr-review-toolkit/agents/silent-failure-hunter.md",
    "plugins/pr-review-toolkit/agents/type-design-analyzer.md",
    "plugins/pr-review-toolkit/commands/review-pr.md",
    "plugins/ralph-wiggum/commands/cancel-ralph.md",
    "plugins/ralph-wiggum/commands/help.md",
    "plugins/ralph-wiggum/commands/ralph-loop.md",
    "plugins/ralph-wiggum/hooks/stop-hook.sh",
    "plugins/ralph-wiggum/scripts/setup-ralph-loop.sh",

    # =================================================================================
    # Plugin-dev skills and bundled validators used to generate executable repo content
    # =================================================================================
    "plugins/plugin-dev/agents/agent-creator.md",
    "plugins/plugin-dev/agents/plugin-validator.md",
    "plugins/plugin-dev/agents/skill-reviewer.md",
    "plugins/plugin-dev/commands/create-plugin.md",
    "plugins/plugin-dev/skills/agent-development/SKILL.md",
    "plugins/plugin-dev/skills/agent-development/scripts/validate-agent.sh",
    "plugins/plugin-dev/skills/command-development/SKILL.md",
    "plugins/plugin-dev/skills/hook-development/SKILL.md",
    "plugins/plugin-dev/skills/hook-development/scripts/hook-linter.sh",
    "plugins/plugin-dev/skills/hook-development/scripts/test-hook.sh",
    "plugins/plugin-dev/skills/hook-development/scripts/validate-hook-schema.sh",
    "plugins/plugin-dev/skills/mcp-integration/SKILL.md",
    "plugins/plugin-dev/skills/plugin-settings/SKILL.md",
    "plugins/plugin-dev/skills/plugin-settings/scripts/parse-frontmatter.sh",
    "plugins/plugin-dev/skills/plugin-settings/scripts/validate-settings.sh",
    "plugins/plugin-dev/skills/plugin-structure/SKILL.md",
    "plugins/plugin-dev/skills/skill-development/SKILL.md",

    # =================================================================================
    # Other shipped skills and hook handlers that influence runtime behavior
    # =================================================================================
    "plugins/claude-opus-4-5-migration/skills/claude-opus-4-5-migration/SKILL.md",
    "plugins/explanatory-output-style/hooks-handlers/session-start.sh",
    "plugins/frontend-design/skills/frontend-design/SKILL.md",
    "plugins/learning-output-style/hooks-handlers/session-start.sh",
]


target_scopes = [
    "Critical. An unprivileged attacker controlling only normal Claude Code inputs such as repository files, slash-command arguments, plugin content, hook rule files, issue or PR text, git metadata, or MCP/tool output can bypass command-execution approval or other user-consent boundaries and cause Claude Code to run shell commands, edit files, or invoke tools the user did not authorize.",
    "Critical. An unprivileged attacker can turn untrusted repository or plugin content into arbitrary file read/write outside the intended workspace boundary, unauthorized access to sensitive local files, or exfiltration of API tokens, auth material, prompts, diffs, or other confidential project data to a remote sink.",
    "Critical. An unprivileged attacker can abuse hook parsing, rule evaluation, command frontmatter, agent prompts, or plugin wiring to silently disable, weaken, or route around deny/block security controls so dangerous operations execute when Claude Code or the user expects them to be stopped.",
    "High. An unprivileged attacker can cause cross-repo, cross-session, or cross-target confusion so automation, review, labeling, commenting, or commit flows act on the wrong repository, wrong issue/PR, wrong diff baseline, or wrong filesystem target with real security impact.",
    "High. An unprivileged attacker can use prompt, diff, path, markdown, or config parsing differentials to smuggle unsafe tool instructions, broaden allowed-tools scope, or make trusted validation logic interpret attacker input differently from the downstream execution path.",
    "High. An unprivileged attacker can cause Claude Code security-review or automation components to leak private code, secrets, or sensitive metadata to external model or network endpoints beyond the intended reviewed scope or consent boundary.",
]


scope_scan = [
]


def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit and fuzzing questions for one claude-code target.

    ```
    target_file format:
    "'File Name: plugins/hookify/core/config_loader.py -> Scope: Critical. ...'"
    """

    prompt = f"""
    ```

    Generate exploit-focused security audit and fuzzing questions for this exact claude-code target:

    {target_file}

    Project focus:
    Claude Code is a local agentic coding and plugin ecosystem. Focus on command approval boundaries, hook enforcement, tool and file-write authorization, workspace confinement, untrusted repo or plugin content, prompt/frontmatter parsing, git-driven automation, and secret/code disclosure to local or remote sinks.

    Rules:
    * Treat `File Name:` as the exact file/module.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Use exact Python/TS/Shell/Markdown symbols when possible.
    * Attacker is unprivileged only: no employee/admin access, no prior shell on the victim machine, no leaked keys, no privileged plugin install rights, no malicious node/peer, no phishing, and no social engineering.
    * Allowed attacker inputs are normal external surfaces: cloned repository content, checked-in plugin files, slash-command arguments, markdown/frontmatter content, hook rule files, issue/PR text, git branch/commit metadata, MCP/tool/API responses, and other data Claude Code normally reads or executes against.
    * Ignore test files, mock files, docs, generated files, config-only findings, and dependency-only issues.
    * Do not rely on impossible operator-only setup, victim self-compromise with their own local config only, or assumptions that a malicious maintainer already has privileged control of the machine.
    * Generate 12 to 16 high-signal questions.
    * At least 70% must target approval bypass, hook or guard bypass, unsafe file or command execution, workspace escape, secret exfiltration, parser differentials, or untrusted repo/plugin trust-boundary failures.
    * Every question must be testable by unit test, integration test, fuzz test, invariant test, or differential test.
    * Avoid generic checklist questions and repeated root causes.

    Core invariants:
    * Consent is explicit and scoped: shell execution, file mutation, networked tool use, and automation side effects must stay bound to the user-approved target, repo, and permission state.
    * Deny means deny: block hooks, approval gates, allowed-tools restrictions, and workspace boundaries must not be bypassable through parsing tricks, alternate call paths, or stale state.
    * Secrets stay secret: tokens, auth headers, prompts, diffs, local file contents, and private project data must not become readable or exfiltratable by an unprivileged attacker.
    * Untrusted repo or plugin content must not silently become executable authority or broaden Claude Code capabilities beyond what the user explicitly approved.
    * State must stay correctly bound: session, diff, repo, issue/PR, and filesystem targets must not drift or cross between principals.

    Each question must include:
    1. target function/module;
    2. attacker action;
    3. preconditions;
    4. call sequence;
    5. invariant tested;
    6. scoped impact;
    7. proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Function: symbol_or_module] Can an unprivileged ATTACKER_ACTION under PRECONDITIONS trigger CALL_SEQUENCE, violating INVARIANT, causing scoped impact: SCOPE_IMPACT? Proof idea: unit/integration/fuzz PARAMETERS and assert APPROVAL_BOUNDARY, SECRET_ISOLATION, WORKSPACE_CONFINEMENT, or TARGET_BINDING.",
    ]
    """
    return prompt


def audit_format(security_question: str) -> str:
    """
    Generate a focused claude-code exploit-validation prompt.
    """

    prompt = f"""# SECURITY AUDIT PROMPT

## Question
{security_question}

## Rules
- Use existing repo context only. Analyze only this question and scoped impact.
- Attacker is unprivileged only: no admin or maintainer privilege on the victim machine, no leaked keys, no social engineering, and no malicious node/peer/operator assumptions.
- Reject anything that depends only on test/mock/config/docs/generated files, dependency bugs alone, direct store mutation from tests, or best-practice cleanup without exploitable impact.
- Focus on real Claude Code compromise paths reachable from ordinary repository content, plugin files, slash-command input, hook/frontmatter parsing, git metadata, issue/PR text, MCP/tool/API responses, or normal automation flows.

## Validate
- Trace the exact reachable path from the attacker input into hook enforcement, command execution, file mutation, git automation, review/export logic, or networked tool calls.
- Check whether existing validation, approval prompts, allowlists, workspace guards, session binding, repo scoping, or parser checks already stop it.
- Accept only real approval bypass, unauthorized command or file action, workspace escape, secret disclosure, trust-boundary bypass, or direct user/project compromise behavior.
- Require exact file/function support and a reproducible unit/integration/fuzz/invariant PoC.

## Output
If valid, output exactly:

### Title
[Bug statement] - ([File: file_path])

### Summary
[2-3 sentences]

### Finding Description
[Code path, root cause, attacker inputs, exploit flow, and why checks fail]

### Impact Explanation
[Concrete scoped impact and matching Claude Code bounty impact]

### Likelihood Explanation
[Preconditions, feasibility, repeatability]

### Recommendation
[Specific fix]

### Proof of Concept
[Unit/integration test or fuzz/invariant test plan with expected assertions]

If invalid, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict bounty-style validation prompt for claude-code security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and Researcher.Md for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- Reject malicious-node, malicious-peer, operator-only, leaked-key, dependency-only, docs/style, generated-file, test/mock/config-only, self-XSS-only, and purely theoretical issues.
- Reject if the exploit needs victim social engineering, impossible setup, or unsupported behavior outside normal Claude Code inputs.
- Reject if the bug was fixed, acknowledged, or publicly disclosed already, per the eligibility rules.
- A valid report must be triggerable by an unprivileged user, unless the claim proves privilege escalation from an unprivileged path.
- The final impact must map to an in-scope Claude Code impact such as permission-modal bypass, unauthorized shell or file action, workspace escape, secret/code disclosure, hook bypass, or direct compromise of user projects or local trust boundaries.
- Prefer #NoVulnerability over speculative reports.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken security assumption.
3. Reachable exploit path: preconditions -> attacker action -> trigger -> bad result.
4. Existing checks/guards reviewed and shown insufficient.
5. Concrete in-scope impact with realistic likelihood.
6. Reproducible proof path: unit PoC, integration test, invariant/fuzz test, or exact manual steps.
7. No obvious rejection reason from SECURITY.md, known issues, privilege assumptions, or scope exclusions.

## Silent Triage Questions
Before output, internally answer:
- Can a normal external user trigger this through real repository, plugin, command, hook, git, or tool surfaces without privileged access?
- Does the code actually behave as claimed?
- Is the impact caused by this code, not by a malicious node, peer, repository operator already holding privileged machine access, or dependency alone?
- Is the unauthorized execution, disclosure, bypass, or local/project compromise concrete, not hypothetical?
- Would a Claude Code bounty triager accept the proof?
- What exact test would prove it?

## Output
If valid, output exactly:

Audit Report

## Title
[Clear vulnerability statement] - ([File: file_path])

## Summary
[2-3 sentence summary of the bug and impact]

## Finding Description
[Exact code path, root cause, exploit flow, and why existing checks fail]

## Impact Explanation
[Concrete in-scope impact, severity rationale, and Claude Code bounty category]

## Likelihood Explanation
[Attacker capability, required conditions, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or fuzz/invariant/integration test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for claude-code.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Rules
- Use in-scope production repo context only. Do not ask for code or claim missing files.
- Use the external report only as a bug-class hint, not as proof.
- Keep only unprivileged-user analogs in command approval, hook bypass, workspace escape, prompt/frontmatter parsing, git automation, tool authorization, or secret/code disclosure trust boundaries.
- Reject malicious-node/peer/operator analogs, mocked-only paths, dependency-only bugs, and no-impact or self-XSS-only analogs.

## Validate
- Map the bug class to the strongest reachable claude-code path.
- Prove root cause with exact file/function support.
- Accept only concrete approval bypass, unauthorized shell/file action, secret disclosure, workspace escape, cross-target automation bleed, or direct local/project compromise impact.

## Output (Strict)
If valid analog exists, output:

### Title
[Clear vulnerability statement] - ([File: file_path])

### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If not, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt
