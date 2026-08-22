import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the GitLab namespace/project path, for example group/project
SOURCE_REPO = 'cli/cli'
# todo: the name of the repository
REPO_NAME = 'cli'

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
    # Auth: token storage, login/logout flows, git credential helper, OAuth scopes
    # =================================================================================
    "internal/config/config.go",
    "internal/config/migration/multi_account.go",
    "internal/keyring/keyring.go",
    "internal/authflow/flow.go",
    "internal/authflow/success.go",
    "pkg/cmd/auth/login/login.go",
    "pkg/cmd/auth/logout/logout.go",
    "pkg/cmd/auth/refresh/refresh.go",
    "pkg/cmd/auth/token/token.go",
    "pkg/cmd/auth/switch/switch.go",
    "pkg/cmd/auth/setupgit/setupgit.go",
    "pkg/cmd/auth/gitcredential/helper.go",
    "pkg/cmd/auth/shared/login_flow.go",
    "pkg/cmd/auth/shared/git_credential.go",
    "pkg/cmd/auth/shared/gitcredentials/helper_config.go",
    "pkg/cmd/auth/shared/gitcredentials/updater.go",
    "pkg/cmd/auth/shared/oauth_scopes.go",
    "pkg/cmd/auth/shared/writeable.go",

    # =================================================================================
    # HTTP client, host trust, redirects, repo/host resolution from untrusted remotes
    # =================================================================================
    "api/client.go",
    "api/http_client.go",
    "internal/ghinstance/host.go",
    "internal/ghrepo/repo.go",
    "internal/safeurl/safeurl.go",
    "internal/safepaths/absolute.go",
    "context/remote.go",
    "pkg/cmd/factory/default.go",
    "pkg/cmd/factory/remote_resolver.go",
    "pkg/cmdutil/repo_override.go",
    "pkg/cmdutil/file_input.go",
    "pkg/cmd/api/api.go",
    "pkg/cmd/api/http.go",
    "pkg/cmd/api/pagination.go",
    "pkg/cmd/api/fields.go",

    # =================================================================================
    # Git invocation and URL/ref handling driven by attacker-controlled repo metadata
    # =================================================================================
    "git/client.go",
    "git/command.go",
    "git/url.go",
    "git/objects.go",
    "pkg/cmd/repo/clone/clone.go",
    "pkg/cmd/repo/fork/fork.go",
    "pkg/cmd/repo/sync/git.go",
    "pkg/cmd/repo/sync/sync.go",
    "pkg/cmd/repo/setdefault/setdefault.go",
    "pkg/cmd/pr/checkout/checkout.go",
    "pkg/cmd/pr/shared/worktree.go",
    "pkg/cmd/pr/shared/finder.go",
    "pkg/cmd/issue/develop/develop.go",
    "pkg/cmd/gist/clone/clone.go",

    # =================================================================================
    # Extensions: discovery, install, upgrade, symlink, and local execution
    # =================================================================================
    "pkg/cmd/extension/manager.go",
    "pkg/cmd/extension/command.go",
    "pkg/cmd/extension/extension.go",
    "pkg/cmd/extension/git.go",
    "pkg/cmd/extension/http.go",
    "pkg/cmd/extension/symlink_other.go",
    "pkg/cmd/extension/symlink_windows.go",
    "pkg/cmd/extension/browse/browse.go",
    "pkg/extensions/extension.go",
    "pkg/extensions/official.go",
    "pkg/cmd/root/extension.go",
    "pkg/cmd/root/root.go",
    "pkg/cmd/root/alias.go",
    "internal/ghcmd/cmd.go",
    "internal/run/run.go",

    # =================================================================================
    # Skills: remote package fetch, unpack, frontmatter, lockfile pinning, discovery
    # =================================================================================
    "internal/skills/installer/installer.go",
    "internal/skills/source/source.go",
    "internal/skills/registry/registry.go",
    "internal/skills/frontmatter/frontmatter.go",
    "internal/skills/lockfile/lockfile.go",
    "internal/skills/discovery/discovery.go",
    "internal/skills/discovery/collisions.go",
    "pkg/cmd/skills/install/install.go",
    "pkg/cmd/skills/update/update.go",
    "pkg/cmd/skills/preview/preview.go",
    "pkg/cmd/skills/publish/publish.go",

    # =================================================================================
    # Attestation and artifact signature verification (supply-chain trust decisions)
    # =================================================================================
    "pkg/cmd/attestation/verify/verify.go",
    "pkg/cmd/attestation/verify/policy.go",
    "pkg/cmd/attestation/verify/attestation.go",
    "pkg/cmd/attestation/verify/options.go",
    "pkg/cmd/attestation/verification/sigstore.go",
    "pkg/cmd/attestation/verification/policy.go",
    "pkg/cmd/attestation/verification/attestation.go",
    "pkg/cmd/attestation/verification/extensions.go",
    "pkg/cmd/attestation/verification/tuf.go",
    "pkg/cmd/attestation/api/client.go",
    "pkg/cmd/attestation/api/attestation.go",
    "pkg/cmd/attestation/api/trust_domain.go",
    "pkg/cmd/attestation/artifact/artifact.go",
    "pkg/cmd/attestation/artifact/file.go",
    "pkg/cmd/attestation/artifact/image.go",
    "pkg/cmd/attestation/artifact/digest/digest.go",
    "pkg/cmd/attestation/artifact/oci/client.go",
    "pkg/cmd/attestation/trustedroot/trustedroot.go",
    "pkg/cmd/attestation/download/download.go",
    "pkg/cmd/attestation/inspect/bundle.go",
    "pkg/cmd/release/verify-asset/verify_asset.go",
    "pkg/cmd/release/verify/verify.go",
    "pkg/cmd/release/shared/attestation.go",

    # =================================================================================
    # Downloading remote-controlled content to the local filesystem
    # =================================================================================
    "pkg/cmd/release/shared/fetch.go",
    "pkg/cmd/release/download/download.go",
    "pkg/cmd/run/download/download.go",
    "pkg/cmd/run/download/http.go",
    "pkg/cmd/run/shared/artifacts.go",
    "pkg/cmd/run/view/logs.go",
    "internal/zip/zip.go",
    "pkg/cmd/repo/read-file/read_file.go",
    "pkg/cmd/repo/read-dir/read_dir.go",
    "pkg/cmd/gist/shared/shared.go",
    "pkg/cmd/gist/edit/edit.go",
    "pkg/cmd/gist/view/view.go",
    "pkg/cmd/gist/create/create.go",

    # =================================================================================
    # Rendering untrusted server content into the user's terminal or browser
    # =================================================================================
    "pkg/iostreams/untrusted.go",
    "pkg/iostreams/iostreams.go",
    "pkg/iostreams/content.go",
    "pkg/markdown/markdown.go",
    "internal/text/text.go",
    "internal/tableprinter/table_printer.go",
    "pkg/cmd/pr/view/view.go",
    "pkg/cmd/issue/view/view.go",
    "pkg/cmd/pr/shared/display.go",
    "pkg/cmd/pr/shared/comments.go",
    "pkg/cmd/pr/checks/output.go",
    "pkg/cmd/browse/browse.go",
    "internal/browser/browser.go",

    # =================================================================================
    # Codespaces: connections, SSH, and port forwarding driven by remote responses
    # =================================================================================
    "internal/codespaces/ssh.go",
    "internal/codespaces/codespaces.go",
    "internal/codespaces/connection/connection.go",
    "internal/codespaces/portforwarder/port_forwarder.go",
    "internal/codespaces/rpc/invoker.go",
    "internal/codespaces/api/api.go",
    "pkg/cmd/codespace/ssh.go",
    "pkg/cmd/codespace/ports.go",
    "pkg/cmd/codespace/code.go",
    "pkg/cmd/codespace/jupyter.go",
    "pkg/cmd/codespace/common.go",

    # =================================================================================
    # Agent tasks, aliases, secrets, keys, and self-update
    # =================================================================================
    "pkg/cmd/agent-task/capi/client.go",
    "pkg/cmd/agent-task/shared/capi.go",
    "pkg/cmd/agent-task/create/create.go",
    "pkg/cmd/copilot/copilot.go",
    "pkg/cmd/alias/set/set.go",
    "pkg/cmd/alias/imports/import.go",
    "pkg/cmd/alias/shared/validations.go",
    "pkg/cmd/secret/set/set.go",
    "pkg/cmd/secret/set/http.go",
    "pkg/cmd/secret/shared/shared.go",
    "pkg/ssh/ssh_keys.go",
    "internal/update/update.go",
]


target_scopes = [
    "Critical. An unprivileged attacker who only publishes content the victim's gh fetches (a repo, fork, PR, issue, gist, release asset, workflow artifact, extension, or skill) achieves arbitrary code or command execution on the victim's machine during an ordinary gh command.",
    "Critical. An unprivileged attacker causes gh to send the victim's OAuth token, git credentials, or codespace token to a host the attacker controls, through host or hostname parsing, redirect handling, remote or submodule URLs, the git credential helper, or a wrong-host authenticated request.",
    "Critical. An unprivileged attacker controls a downloaded name or path (artifact entry, zip member, release asset, gist file, skill or extension file) so gh writes, overwrites, or symlinks outside the intended output directory, reaching startup files, git hooks, or gh's own config and binaries.",
    "Critical. An unprivileged attacker gets `gh attestation verify` or release asset verification to report success for an artifact they built, by defeating digest binding, bundle or DSSE payload checks, certificate SAN, issuer, repo or workflow policy matching, trusted-root or TUF handling.",
    "Critical. An unprivileged attacker uses repo, branch, ref, or remote names they control to inject git options, protocol handlers, or config into gh's git invocations, so clone, fork, sync, pr checkout, or issue develop executes attacker-chosen commands.",
    "High. An unprivileged attacker escalates the credentials or scope gh uses, by making gh select the wrong account or host, persist a token where it should not, expose it via the credential helper or an extension environment, or bypass the intended OAuth scope and confirmation checks.",
    "High. An unprivileged attacker embeds control sequences or crafted markup in issue, PR, check, release, or skill content so gh's terminal or browser output executes commands, spoofs prompts, or opens attacker-chosen URIs.",
    "High. An unprivileged attacker who controls an API response or a repo the victim runs gh in causes gh to read local files, reach internal hosts, or leak private data into an attacker-visible request or an unbounded resource consumption on the victim's machine.",
]


scope_scan = [
]


def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit and fuzzing questions for one GitHub CLI target.

    ```
    target_file format:
    "'File Name: pkg/cmd/extension/manager.go -> Scope: Critical. ...'"
    """

    prompt = f"""
    ```

    Generate exploit-focused security audit and fuzzing questions for this exact GitHub CLI (gh) target:

    {target_file}

    Project focus:
    gh is the GitHub CLI, a Go client that runs on a developer machine with the user's GitHub token. Focus on token handling and host trust, HTTP client and redirect behavior, git command and URL construction, extension and skill install and execution, attestation verification, downloading remote content to disk, and rendering untrusted API content in the terminal.

    Rules:
    * Treat `File Name:` as the exact file/package.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Use exact Go symbols (func, method, struct, field) when possible.
    * Attacker is unprivileged only: any remote GitHub user with no rights on the victim's machine, repos, or org. They can publish repos, forks, PR branches, refs, issues, comments, gists, releases, workflow artifacts, extensions, and skills, and can control the responses of a host the victim points gh at.
    * Attacker is NOT the local user, an admin of the victim's machine, an org or repo owner, a GitHub operator, or a network MITM. Ignore leaked-token, physical-access, local-network, social-engineering, and malicious-maintainer assumptions.
    * The victim only runs ordinary gh commands on attacker-published content; no unusual flags or hand-edited config.
    * Ignore test files, mocks, fixtures, docs, generated code, build scripts, dependency-only bugs, and config-only findings.
    * Generate 12 to 16 high-signal questions.
    * At least 70% must target code execution on the victim host, credential or token exfiltration, writes outside the intended path, verification or authorization bypass, or wrong-host/wrong-account request routing.
    * Every question must be testable by unit test, integration test, fuzz test, or an httpmock/git-stub based test.
    * Avoid generic checklist questions and repeated root causes.

    Core invariants:
    * Credential confinement: a host's token is attached only to requests to that host, never followed across a redirect or a remote/submodule URL to another host, and is never written to a log, argv, env, or extension-visible surface.
    * Host and repo trust: hostnames, remote URLs, and repo overrides parsed from untrusted input resolve to the intended GitHub host, never to an attacker host or a non-HTTPS scheme.
    * No injected execution: values from API responses, git output, repo metadata, or package archives never become git options, shell words, executable paths, or URI handlers.
    * Path confinement: every file written from remote content stays inside the chosen output directory after decoding, symlink resolution, and case or Unicode normalization.
    * Verification is sound: a verify success means the bundle's signature, digest, certificate identity, and policy all bound the exact artifact to the claimed repo and workflow.
    * Output safety: untrusted text is sanitized before reaching a terminal, pager, or browser, and cannot forge gh's own prompts or trusted output.

    Each question must include:
    1. target function/package;
    2. attacker action;
    3. preconditions;
    4. call sequence;
    5. invariant tested;
    6. scoped impact;
    7. proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Function: symbol_or_package] Can an unprivileged ATTACKER_ACTION under PRECONDITIONS trigger CALL_SEQUENCE, violating INVARIANT, causing scoped impact: SCOPE_IMPACT? Proof idea: unit/integration/fuzz PARAMETERS and assert CREDENTIAL_CONFINEMENT, HOST_TRUST, NO_INJECTED_EXECUTION, PATH_CONFINEMENT, or VERIFICATION_SOUNDNESS.",
    ]
    """
    return prompt


def audit_format(security_question: str) -> str:
    """
    Generate a focused GitHub CLI exploit-validation prompt.
    """

    prompt = f"""# SECURITY AUDIT PROMPT

## Question
{security_question}

## Rules
- Use existing repo context only. Analyze only this question and scoped impact.
- Attacker is unprivileged only: a remote GitHub user who publishes repos, forks, PR branches and refs, issues, comments, gists, releases, artifacts, extensions, or skills, or controls responses from a host the victim points gh at. No local access, no admin or org rights, no leaked token, no MITM, no social engineering.
- The victim runs ordinary gh commands on that attacker-published content.
- Reject anything that depends only on test/mock/fixture/docs/generated files, dependency bugs alone, or best-practice cleanup without exploitable impact.
- Focus on real compromise paths: code execution on the victim host, token or credential exfiltration, file write or overwrite outside the intended path, attestation or authorization bypass, and wrong-host or wrong-account request routing.

## Validate
- Trace the exact reachable path from attacker-controlled input (API response field, repo or ref name, remote URL, archive entry, bundle, or terminal-bound text) into the affected function.
- Check whether existing validation already stops it: host allowlists, safeurl, safepaths, ghrepo/ghinstance parsing, git argument handling, zip path checks, sigstore policy, or output sanitization.
- Accept only concrete impact: command or code execution, credential disclosure, arbitrary file write or read, verification bypass, or authenticated request to an attacker host.
- Require exact file/function support and a reproducible Go test, httpmock, git-stub, or fuzz PoC.

## Output
If valid, output exactly:

### Title
[Bug statement] - ([File: file_path])

### Summary
[2-3 sentences]

### Finding Description
[Code path, root cause, attacker inputs, exploit flow, and why checks fail]

### Impact Explanation
[Concrete scoped impact and matching GitHub bounty impact class]

### Likelihood Explanation
[Preconditions, feasibility, repeatability]

### Recommendation
[Specific fix]

### Proof of Concept
[Go unit/integration test, httpmock or git-stub scenario, or fuzz plan with expected assertions]

If invalid, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict bounty-style validation prompt for GitHub CLI security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and Researcher.Md for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- Reject local-attacker, admin/org-owner, GitHub-operator, MITM, leaked-token, physical-access, local-network, social-engineering, dependency-only, docs/style, generated-file, and test/mock/config-only issues.
- Reject if the exploit needs the victim to hand-edit config, run unusual flags, or perform steps outside a normal gh workflow.
- Reject if the bug was fixed, acknowledged, or publicly disclosed already, per the eligibility rules.
- A valid report must be triggerable by a remote unprivileged GitHub user through content they publish or a host they control, unless the claim proves escalation from that unprivileged position.
- The final impact must map to an in-scope GitHub impact such as code execution on the victim machine, token or credential exfiltration, arbitrary file write or overwrite, arbitrary local file read or exfiltration, attestation or signature verification bypass, or authentication/authorization bypass in gh.
- Prefer #NoVulnerability over speculative reports.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken trust assumption.
3. Reachable exploit path: preconditions -> attacker-published content or controlled host -> victim gh command -> bad result.
4. Existing checks (host allowlist, safeurl, safepaths, ghrepo parsing, git argument handling, zip path checks, sigstore policy, output sanitization) reviewed and shown insufficient.
5. Concrete in-scope impact with realistic likelihood for a normal gh workflow.
6. Reproducible proof path: Go unit PoC, httpmock/git-stub integration test, fuzz test, or exact steps against a real repo.
7. No obvious rejection reason from SECURITY.md, known issues, privilege assumptions, or scope exclusions.

## Silent Triage Questions
Before output, internally answer:
- Can a remote unprivileged GitHub user trigger this with content they publish, without local or admin access?
- Does the code actually behave as claimed on the current trunk?
- Is the impact caused by this code, not by git, a dependency, or the user's own configuration?
- Is the execution, credential leak, file write, or verification bypass concrete, not hypothetical?
- Would a GitHub bounty triager accept the proof?
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
[Concrete in-scope impact, severity rationale, and GitHub bounty category]

## Likelihood Explanation
[Attacker capability, required conditions, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or Go test/fuzz plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for the GitHub CLI.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Rules
- Use in-scope production repo context only. Do not ask for code or claim missing files.
- Use the external report only as a bug-class hint, not as proof.
- Keep only unprivileged remote-attacker analogs in token handling and host trust, HTTP client and redirects, git command and URL construction, extension or skill install and execution, attestation verification, downloads to disk, or untrusted terminal output.
- Reject local-attacker, admin/operator-only, MITM, leaked-token, mocked-only paths, dependency-only bugs, and no-impact analogs.

## Validate
- Map the bug class to the strongest reachable gh path from attacker-published content or an attacker-controlled host during a normal gh command.
- Prove root cause with exact file/function support.
- Accept only concrete code execution, credential exfiltration, file write or read outside the intended path, verification bypass, or authenticated request sent to an attacker host.

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
