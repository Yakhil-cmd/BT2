import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 5
# todo: the GitLab namespace/project path, for example group/project
SOURCE_REPO = 'kubernetes/git-sync'
# todo: the name of the repository
REPO_NAME = 'git-sync'

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
    # Core sync engine: fetch, worktree create/configure, submodules, symlink publish,
    # cleanup, credential setup, askpass/GitHub-App auth, git config parsing, HTTP server
    # =================================================================================
    "main.go",

    # =================================================================================
    # Path handling used for --root, worktrees and the published --link symlink
    # =================================================================================
    "abspath.go",

    # =================================================================================
    # Credential flag decoding and secret handling
    # =================================================================================
    "credential.go",

    # =================================================================================
    # Env/flag parsing that feeds every sync parameter
    # =================================================================================
    "env.go",

    # =================================================================================
    # Subprocess execution: git and hook command invocation, env and stdin handling
    # =================================================================================
    "pkg/cmd/cmd.go",

    # =================================================================================
    # Hooks fired on every successful sync with attacker-influenced hash/worktree data
    # =================================================================================
    "pkg/hook/hook.go",
    "pkg/hook/exechook.go",
    "pkg/hook/webhook.go",

    # =================================================================================
    # Logging and error-file export written inside --root
    # =================================================================================
    "pkg/logging/logging.go",

    # =================================================================================
    # PID-1 re-exec and child reaping inside the container
    # =================================================================================
    "pkg/pid1/pid1.go",
]


target_scopes = [
    "Critical. An unprivileged attacker who can only push a commit, branch, or tag to the synced repository achieves command execution inside the git-sync container through git-controlled mechanisms reachable from fetch, reset, or `submodule update` (for example .gitmodules `ext::`/`file::` URLs, in-repo hooks, .gitattributes filters, or config-driven helpers).",
    "Critical. Repository-controlled content (submodule paths, symlinks, filenames, .git file rewriting in configureWorktree) makes git-sync create, overwrite, or delete files outside the --root directory, letting the attacker plant code or config into the container filesystem or a co-mounted volume.",
    "Critical. Repository-controlled content or refs cause git-sync to leak its own secrets - GITSYNC_PASSWORD, the git credential store, SSH key, cookie file, askpass response, or GitHub App installation token - into the published worktree, logs, error file, metrics, or an attacker-controlled network endpoint.",
    "Critical. The published --link symlink is made to point at content that is not the requested ref, at a partially built or still-mutable worktree, or at a path outside --root, so the consuming workload loads attacker-chosen code while git-sync reports a successful sync.",
    "Critical. Attacker-controlled ref names, hashes, remote URLs, or submodule values flow unescaped into git argv (Runner.Run/RunWithStdin) or into exec-hook argv/env, giving git option injection or command execution with git-sync's credentials.",
    "High. Attacker-controlled repository state permanently wedges syncing - panic, deadlock, unhandled error loop, stale lock file, or failed worktree cleanup - while getRepoReady/setRepoReady and the health endpoint still report ready, freezing consumers on stale content.",
    "High. Attacker-controlled repository content exhausts the volume or container memory (oversized blobs or history, deep or recursive submodules, accumulated stale worktrees that removeStaleWorktrees/cleanup fails to reclaim), causing denial of service for the pod or node.",
    "High. In-repo files influence git-sync's effective git configuration for later syncs (SetupDefaultGitConfigs, SetupExtraGitConfigs, parseGitConfigs, safe.directory, sparse-checkout, worktree .git file), giving the attacker persistence across sync cycles or across restarts.",
    "High. Checked-out repository content is published with unsafe modes or ownership (setuid/setgid bits, world-writable files, symlinks into host mounts, addUser/passwd handling), letting an unprivileged process in a co-mounted container escalate or tamper with synced data.",
    "High. A sync of a moved tag, force-pushed branch, shallow fetch, or hash ref silently publishes content that does not match the requested revision or is never updated again, breaking the hash-in-symlink contract that consumers rely on for integrity.",
]


scope_scan = [
]


def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit and fuzzing questions for one git-sync target.

    ```
    target_file format:
    "'File Name: main.go -> Scope: Critical. ...'"
    """

    prompt = f"""
    ```

    Generate exploit-focused security audit and fuzzing questions for this exact git-sync target:

    {target_file}

    Project focus:
    git-sync is a Kubernetes sidecar that clones a remote git repo into --root and publishes each sync via the --link symlink for another container to consume. Focus on fetch and checkout of untrusted repo content, submodule handling, symlink publish and cleanup, path handling under --root, git argv construction, credential/askpass/GitHub-App secret handling, git config setup, and exec/web hooks.

    Rules:
    * Treat `File Name:` as the exact file/module.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Use exact Go symbols (func, method, struct, field, flag name) when possible.
    * Attacker is unprivileged only: someone who can push a commit, branch, or tag to the synced repository, or otherwise control the repo content and refs git-sync fetches, plus any process that can reach git-sync's HTTP port or read the --root volume as a non-root user.
    * Attacker is NOT the operator: they cannot set git-sync flags, env vars, secrets, mounts, or the Pod spec, and cannot exec into the container. Ignore malicious-operator, malicious-node, leaked-key, and social-engineering assumptions.
    * Ignore test files, mocks, e2e scripts, docs, Makefile/Dockerfile/build tooling, generated files, and dependency-only issues.
    * Ignore findings that need a non-default flag combination that no sane deployment would use; note the flags required when the path is opt-in but documented.
    * Generate 30 to 40 high-signal questions.
    * At least 70% must target code execution from repo content, file writes outside --root, secret leakage, symlink/publish integrity, git argv or config injection, or permanent sync wedging.
    * Every question must be testable by unit test, integration test, fuzz test, or a scripted local git server repo.
    * Avoid generic checklist questions and repeated root causes.

    Core invariants:
    * Content containment: fetched repo content is data only - it never executes code in the git-sync container and never causes writes, deletes, or links outside --root.
    * Publish integrity: the --link symlink only ever points to a fully built worktree inside --root whose leaf name is the hash of the exact requested revision.
    * Secret confinement: credentials, SSH keys, cookie files, and tokens stay inside git-sync's private state and never reach the published worktree, logs, error file, hook payloads, or an unintended host.
    * Argv and config integrity: no repo-controlled string becomes a git option, a git config value, or a hook argument/env value that changes behavior.
    * Liveness and honesty: no repo state can permanently stop syncing, exhaust the volume, or leave readiness and metrics claiming success while data is stale.

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
    "[File: {target_file}] [Function: symbol_or_module] Can an unprivileged ATTACKER_ACTION under PRECONDITIONS trigger CALL_SEQUENCE, violating INVARIANT, causing scoped impact: SCOPE_IMPACT? Proof idea: unit/integration/fuzz PARAMETERS and assert CONTENT_CONTAINMENT, PUBLISH_INTEGRITY, SECRET_CONFINEMENT, ARGV_OR_CONFIG_INTEGRITY, or LIVENESS_AND_HONESTY.",
    ]
    """
    return prompt


def audit_format(security_question: str) -> str:
    """
    Generate a focused git-sync exploit-validation prompt.
    """

    prompt = f"""# SECURITY AUDIT PROMPT

## Question
{security_question}

## Rules
- Use existing repo context only. Analyze only this question and scoped impact.
- Attacker is unprivileged only: they control repo content and refs that git-sync fetches, or can reach its HTTP port or read the --root volume as a non-root user. They do NOT control flags, env vars, secrets, mounts, or the Pod spec, and cannot exec into the container.
- Reject malicious-operator, malicious-node, leaked-key, social-engineering, and misconfiguration-only paths.
- Reject anything that depends only on test/mock/e2e/docs/build/generated files, dependency bugs alone, or best-practice cleanup without exploitable impact.
- Focus on real compromise paths: code execution from repo content, writes or deletes outside --root, secret leakage, symlink/publish integrity failure, git argv or config injection, and permanent sync wedging or resource exhaustion.

## Validate
- Trace the exact reachable path from attacker-controlled repo content, ref name, or HTTP request into the affected function.
- Check whether existing validation, flag defaults, git's own protections (fsck, protocol.allow, safe.directory), path handling in absPath, or error handling already stops it.
- Name any non-default flags the path requires and confirm they are documented, supported settings.
- Accept only code execution, file writes outside --root, secret disclosure, publishing wrong or partial content, or a persistent stall/exhaustion that a consumer would suffer.
- Require exact file/function support and a reproducible unit/integration/fuzz PoC.

## Output
If valid, output exactly:

### Title
[Bug statement] - ([File: file_path])

### Summary
[2-3 sentences]

### Finding Description
[Code path, root cause, attacker inputs, exploit flow, and why checks fail]

### Impact Explanation
[Concrete scoped impact and matching Kubernetes bounty impact class]

### Likelihood Explanation
[Preconditions, required flags, feasibility, repeatability]

### Recommendation
[Specific fix]

### Proof of Concept
[Unit/integration test or local-git-server repro with expected assertions]

If invalid, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict bounty-style validation prompt for git-sync security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and Researcher.Md for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- Reject malicious-operator, malicious-node, leaked-key, dependency-only, docs/style, generated-file, build-tooling, test/mock/e2e-only, and purely theoretical issues.
- Reject if the exploit needs control of git-sync flags, env vars, secrets, mounts, the Pod spec, or shell access to the container.
- Reject if the bug was fixed, acknowledged, or publicly disclosed already, per the eligibility rules.
- A valid report must be triggerable by someone who only controls repo content/refs, the git-sync HTTP port, or non-root access to the --root volume, unless the claim proves escalation from such a position.
- The final impact must map to an in-scope class: code execution in the git-sync or consumer container, file write/delete outside --root, disclosure of credentials or tokens, publishing content that does not match the requested revision, or persistent denial of sync with dishonest readiness.
- Prefer #NoVulnerability over speculative reports.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken assumption about untrusted repo content.
3. Reachable exploit path: preconditions -> attacker commit/ref/request -> trigger -> bad result.
4. Existing checks, path handling, git defaults, and error handling reviewed and shown insufficient.
5. Concrete in-scope impact with realistic likelihood and clearly stated flag requirements.
6. Reproducible proof path: unit PoC, integration test, fuzz test, or exact steps against a local git server and a real git-sync run.
7. No obvious rejection reason from SECURITY.md, known issues, privilege assumptions, or scope exclusions.

## Silent Triage Questions
Before output, internally answer:
- Can someone who only pushes to the repo, hits the HTTP port, or reads the volume trigger this without operator access?
- Does the code actually behave as claimed on the current master branch and default flags?
- Is the impact caused by this code, not by git itself, the operator's config, or a dependency alone?
- Is the execution, file write, secret disclosure, wrong-content publish, or stall concrete, not hypothetical?
- Would a Kubernetes security triager accept the proof?
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
[Concrete in-scope impact, severity rationale, and bounty category]

## Likelihood Explanation
[Attacker capability, required conditions, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or unit/integration test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for git-sync.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Rules
- Use in-scope production repo context only. Do not ask for code or claim missing files.
- Use the external report only as a bug-class hint, not as proof.
- Keep only unprivileged analogs reachable from untrusted repo content, ref names, submodules, symlink publish and cleanup, path handling under --root, git argv or config construction, credential/askpass/token handling, or exec/web hooks.
- Reject malicious-operator, malicious-node, leaked-key, mocked-only paths, dependency-only bugs, and no-impact analogs.

## Validate
- Map the bug class to the strongest reachable git-sync path from an attacker-pushed commit, ref, or an HTTP request to git-sync.
- Prove root cause with exact file/function support and state any required flags.
- Accept only code execution, file write or delete outside --root, credential or token disclosure, publishing wrong or partial content, or persistent sync denial.

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
