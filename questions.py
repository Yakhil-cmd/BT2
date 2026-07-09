import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the path from https:///github.com/dfinity/ICRC-1
SOURCE_REPO = "near/threshold-signatures"
# todo: the name of the repository
REPO_NAME = "threshold-signatures"
run_number = os.environ.get('GITHUB_RUN_NUMBER') or os.environ.get('CI_PIPELINE_IID', '0')


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
    "src/lib.rs",
    "src/dkg.rs",
    "src/participants.rs",
    "src/errors.rs",
    "src/thresholds.rs",
    "src/crypto/mod.rs",
    "src/crypto/ciphersuite.rs",
    "src/crypto/commitment.rs",
    "src/crypto/constants.rs",
    "src/crypto/hash.rs",
    "src/crypto/polynomials.rs",
    "src/crypto/random.rs",
    "src/crypto/proofs/mod.rs",
    "src/crypto/proofs/dlog.rs",
    "src/crypto/proofs/dlogeq.rs",
    "src/crypto/proofs/strobe.rs",
    "src/crypto/proofs/strobe_transcript.rs",
    "src/protocol/mod.rs",
    "src/protocol/echo_broadcast.rs",
    "src/protocol/helpers.rs",
    "src/protocol/internal.rs",
    "src/confidential_key_derivation/mod.rs",
    "src/confidential_key_derivation/app_id.rs",
    "src/confidential_key_derivation/ciphersuite.rs",
    "src/confidential_key_derivation/protocol.rs",
    "src/confidential_key_derivation/scalar_wrapper.rs",
    "src/ecdsa/mod.rs",
    "src/ecdsa/ot_based_ecdsa/mod.rs",
    "src/ecdsa/ot_based_ecdsa/presign.rs",
    "src/ecdsa/ot_based_ecdsa/sign.rs",
    "src/ecdsa/ot_based_ecdsa/triples/mod.rs",
    "src/ecdsa/ot_based_ecdsa/triples/batch_random_ot.rs",
    "src/ecdsa/ot_based_ecdsa/triples/bits.rs",
    "src/ecdsa/ot_based_ecdsa/triples/correlated_ot_extension.rs",
    "src/ecdsa/ot_based_ecdsa/triples/generation.rs",
    "src/ecdsa/ot_based_ecdsa/triples/mta.rs",
    "src/ecdsa/ot_based_ecdsa/triples/multiplication.rs",
    "src/ecdsa/ot_based_ecdsa/triples/random_ot_extension.rs",
    "src/ecdsa/robust_ecdsa/mod.rs",
    "src/ecdsa/robust_ecdsa/presign.rs",
    "src/ecdsa/robust_ecdsa/sign.rs",
    "src/frost/mod.rs",
    "src/frost/eddsa/mod.rs",
    "src/frost/eddsa/sign.rs",
    "src/frost/redjubjub/mod.rs",
    "src/frost/redjubjub/sign.rs",
]

target_scopes = [
    "Critical: Unauthorized creation of a valid threshold signature, presignature, key share, or confidential derived key for attacker-chosen inputs",
    "Critical: Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets",
    "High: Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs",
    "High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions",
    "Medium: Griefing or resource-exhaustion by a malicious caller or participant causing unbounded CPU, memory, bandwidth, or non-terminating work beyond documented behavior",
]

def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit + fuzzing questions for one threshold-signatures target.

    ```
    target_file format:
    "'File Name: src/dkg.rs -> Scope: Critical: Unauthorized creation of a valid threshold signature, presignature, key share, or confidential derived key for attacker-chosen inputs'"
    ```
    """

    prompt = f"""
    ```

    Generate exploit-focused security audit and fuzzing questions for this exact threshold-signatures target:

    {target_file}

    Use live context from the project if available: DKG, resharing, refresh, participant lists, reliable broadcast, protocol channels, transcript hashing, proofs of knowledge, OT-based ECDSA triples/presign/sign, robust ECDSA presign/sign, FROST EdDSA signing, confidential key derivation, ciphersuites, and polynomial/accounting helpers.

    Protocol focus:
    This repository implements threshold ECDSA, threshold EdDSA, DKG/resharing/refresh, reliable broadcast, and confidential key derivation. Focus on unauthorized signing, secret leakage, transcript or participant-set confusion, proof bypass, malformed message acceptance, presign misuse, CKD misuse, cross-round/state desynchronization, and broken threshold/accounting invariants reachable from production APIs and protocol message flows.

    Core invariants:

    * DKG, resharing, and refresh must preserve threshold security, participant-set integrity, and public-key consistency.
    * Signing and presigning must not leak secret shares, nonce material, triple material, or enable unauthorized signatures.
    * CKD outputs must remain bound to the intended app id, public key, participant set, and threshold assumptions.
    * Broadcast, transcript, commitment, and proof validation must prevent split-view, replay, equivocation, and malformed-share acceptance.
    * Public APIs and protocol message handlers must reject invalid participant sets, malformed cryptographic inputs, and state mixes that corrupt outputs or permanently break honest execution beyond documented behavior.

    Rules:

    * Treat `File Name:` as the exact file/module.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Attacker is unprivileged: arbitrary library caller, malicious coordinator, malicious participant, malicious message sender, or network peer operating within the documented protocol threat model.
    * Do not rely on leaked keys, host compromise, compromised RNG source outside the repository, dependency compromise, phishing, or malicious modifications by the application embedding this library.
    * Generate 20 to 30 high-signal questions.
    * At least 70% must be multi-step flow, invariant, fuzz, accounting, state-transition, or cross-module questions.
    * Every question must be testable by PoC, unit test, fuzz test, invariant test, or differential test.
    * Avoid generic checklist questions and repeated root causes.
    * Note any question u must target valid issue u think could be possible
    * note dont gnerate questions on unbounded resource exhaustion those are mostly invalid issue

    High-value attack surfaces:

    * Key management flows: keygen, reshare, refresh, participant changes, threshold checks, and zero-share handling.
    * Signing flows: presign generation/consumption, rerandomization, coordinator aggregation, message-hash binding, and signature-share combination.
    * CKD flows: app-id binding, derived-key confidentiality, encryption component aggregation, and participant-weight normalization.
    * Protocol boundaries: reliable broadcast, private/public channel separation, recv/send ordering, transcript hashing, and proof verification.
    * Cryptographic validation: commitment hashes, proof-of-knowledge checks, lagrange interpolation, polynomial commitments, and ciphersuite/domain-separation assumptions encoded in this repo.

    Impact mapping:

    * Critical: Unauthorized creation of a valid threshold signature, presignature, key share, or confidential derived key for attacker-chosen inputs
    * Critical: Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets
    * High: Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs
    * High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions
    * Medium: Griefing or resource-exhaustion by a malicious caller or participant causing unbounded CPU, memory, bandwidth, or non-terminating work beyond documented behavior

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
    "[File: {target_file}] [Function: symbol_or_module] Can an unprivileged ATTACKER_ACTION under PRECONDITIONS trigger CALL_SEQUENCE, violating INVARIANT, causing scoped impact: SCOPE_IMPACT? Proof idea: fuzz/state-test PARAMETERS and assert EXPECTED_PROPERTY.",
    ]
    """
    return prompt


def audit_format(question: str) -> str:
    """
    Generate a focused threshold-signatures exploit-question validation prompt.
    """
    return f"""# QUESTION SCAN PROMPT

## Exploit Question
{question}

## Scope Rules
- Audit only production threshold-signatures code.
- Do not ask for repo contents or claim files are missing.
- Ignore tests, docs, mocks, scripts, configs, build files, IDE files, package metadata, vendored libraries, and local-only fixtures.
- note dont gnerate report on unbounded resource exhaustion those are mostly invalid issue

## Objective
Decide whether the question leads to a real, reachable threshold-signatures vulnerability.
The attacker must be unprivileged and enter through a public library API, protocol message flow, malicious coordinator/participant action, or validation path whose checks are implemented in scope.
The impact must match one of the allowed threshold-signatures impacts below.
Prefer #NoVulnerability unless the path is concrete, local-testable, and bounty-grade.

## Allowed Impact Scope
Only these impacts are valid:
- Critical: Unauthorized creation of a valid threshold signature, presignature, key share, or confidential derived key for attacker-chosen inputs
- Critical: Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets
- High: Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs
- High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions
- Medium: Griefing or resource-exhaustion by a malicious caller or participant causing unbounded CPU, memory, bandwidth, or non-terminating work beyond documented behavior

## Method
1. Trace the attacker-controlled entrypoint.
2. Map it to exact production threshold-signatures files/functions.
3. Check the relevant guard: participant-list checks, threshold bounds, transcript binding, domain separation, commitment/proof validation, broadcast consistency, share aggregation, or coordinator/message validation.
4. Decide whether the questioned invariant can actually break under intended deployment.
5. Prove root cause with file/function/line references.
6. Confirm realistic likelihood and exact scoped impact.
7. Reject if current validation already prevents the exploit.

## Reject Immediately
- Requires leaked keys, trusted host compromise, dependency compromise, malicious integrator behavior outside this repo, or unsupported external assumptions.
- Requires breaking standard cryptographic assumptions instead of exploiting repository logic.
- Only affects tests, docs, configs, scripts, mocks, local fixtures, vendored libraries, or local deployment choices.
- External dependency behavior is the only cause.
- Impact is only logging, observability, local misconfiguration, documented indefinite waiting without a repo-specific bypass, non-security correctness, harmless error, rejected message, or theoretical risk.
- No concrete scoped impact or no realistic exploit path.

## Output
If valid:

### Title
[Clear vulnerability statement] - ([File: file_path])

### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If invalid, output exactly:
#NoVulnerability found for this question.
"""


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for threshold-signatures.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Access Rules (Strict)
- Treat production threshold-signatures files in the provided scope as accessible context.
- Do not claim missing/inaccessible files.
- Do not ask for repository contents.
- Do not scan tests, docs, build files, IDE files, configs, resources, local fixtures, vendored libraries, or package metadata as audited targets.
- note dont gnerate report on unbounded resource exhaustion those are mostly invalid issue

## Objective
Use the external report's vulnerability class as a hint to find valid issues based on the threshold-signatures security scope.
Focus on reachable issues triggered by an unprivileged library caller, malicious participant, malicious coordinator, or message sender where validation is in scope.
Only report an analog if this codebase has its own reachable root cause and the impact matches one of the allowed threshold-signatures impacts below.

## Allowed Impact Scope
Only these impacts are valid:
- Critical: Unauthorized creation of a valid threshold signature, presignature, key share, or confidential derived key for attacker-chosen inputs
- Critical: Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets
- High: Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs
- High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions
- Medium: Griefing or resource-exhaustion by a malicious caller or participant causing unbounded CPU, memory, bandwidth, or non-terminating work beyond documented behavior

## Method
1. Classify vuln type: transcript confusion, proof bypass, participant-set mismatch, signature forgery, secret leakage, replay/equivocation, threshold-state bug, or resource-exhaustion flaw.
2. Map to threshold-signatures components and exact production files.
3. Prove root cause with exact file/function/module/line references.
4. Confirm concrete scoped impact and realistic likelihood.
5. Explain the attacker-controlled entry path and why this repository's code is a necessary vulnerable step.
6. Reject if the impact does not match one of the allowed threshold-signatures impacts above.

## Disqualify Immediately
- No reachable attacker-controlled entry path.
- Requires leaked keys, trusted host compromise, dependency compromise, cryptographic primitive break, or unsupported external assumptions.
- External dependency behavior is the only cause.
- Test/docs/config/build-only issue.
- Theoretical-only issue with no protocol impact.
- Impact is only local misconfiguration, observability noise, logging noise, documented indefinite waiting without a repo-specific trigger, harmless error, or non-security correctness.
- Impact or likelihood missing.

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



def validation_format(report: str) -> str:
    """
    Generate a strict threshold-signatures bounty-style validation prompt for security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and the threshold-signatures security scope for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- Reject admin-only, trusted-operator, leaked-key, host-compromise, broken-crypto-assumption, best-practice, docs/style, config/build-only, and purely theoretical issues.
- Reject if the exploit requires unrealistic assumptions, victim mistakes, phishing/social engineering, third-party application compromise, missing external context, or unsupported protocol behavior.
- A valid report must be triggerable by an unprivileged library caller, malicious participant, malicious coordinator, or by a protocol/message-validation path whose checks are proven insufficient.
- The final impact must match an in-scope bounty impact, not just a generic code bug.
- Reject any issue whose final impact is not one of the allowed threshold-signatures impacts listed below.
- Prefer #NoVulnerability over speculative reports.

## In-Scope Protocol Areas
The claim must affect production in-scope threshold-signatures code or systems, such as:
- DKG, resharing, and refresh: threshold checks, participant membership, proof/commitment validation, and public-key consistency.
- Threshold signing: OT-based ECDSA triples/presign/sign, robust ECDSA presign/sign, rerandomization, and FROST signing flows.
- CKD flows: app-id binding, encrypted derived-key output generation, and participant-weight aggregation.
- Protocol messaging: reliable broadcast, private/public channels, transcript binding, message ordering, and coordinator aggregation.
- Shared cryptographic validation: lagrange interpolation, polynomial commitments, proof systems, ciphersuite/domain-separation logic, and secret-share handling.

Reject third-party applications, tests, docs, examples, mocks, generated files, local deployment helpers, vendored libraries, and issues that only affect local developer tooling unless the submitted claim proves a direct in-scope threshold-signatures security impact.

## Allowed Impact Scope
Only these impacts are valid:
- Critical: Unauthorized creation of a valid threshold signature, presignature, key share, or confidential derived key for attacker-chosen inputs
- Critical: Extraction, reconstruction, or disclosure of private signing shares, aggregate secret material, presign secrets, nonce material, or confidential derived secrets
- High: Corruption of DKG, reshare, refresh, presign, sign, or CKD outputs so honest parties accept inconsistent public keys, participant sets, transcripts, or unusable cryptographic outputs
- High: Permanent denial of signing, key generation, reshare, refresh, or CKD for honest parties under valid protocol inputs and documented trust assumptions
- Medium: Griefing or resource-exhaustion by a malicious caller or participant causing unbounded CPU, memory, bandwidth, or non-terminating work beyond documented behavior

Informational, non-security correctness, observability/logging-only, harmless reject/revert, stale read without consensus/state/accounting/security impact, local misconfiguration, and non-demonstrably-exploitable reports are invalid for this validation output.

If the submitted claim does not concretely prove one of the allowed threshold-signatures impacts above, it is invalid.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken protocol/security/accounting/authentication/certification assumption.
3. Reachable exploit path: preconditions -> attacker action -> trigger -> bad result.
4. Existing checks/guards reviewed and shown insufficient.
5. Concrete impact that exactly matches one allowed threshold-signatures impact above, with realistic likelihood.
6. Reproducible safe proof path: unit PoC, deterministic integration test, invariant test, fuzz test, or exact local manual steps.
7. No obvious rejection reason from SECURITY.md, known issues, privileges, or scope exclusions.

## Silent Triage Questions
Before output, internally answer:
- Can a normal external caller, malicious participant, malicious coordinator, or insufficiently checked protocol message path trigger this?
- Does the code actually behave as claimed?
- Is the impact caused by threshold-signatures production code, not by an external dependency alone?
- Is the signature/secret/corruption/availability impact concrete, not hypothetical?
- Does the claim avoid leaked keys, host compromise, broken-crypto assumptions, and third-party compromise assumptions?
- Would a bounty triager accept the proof?
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
[Concrete allowed threshold-signatures security impact and severity rationale]

## Likelihood Explanation
[Attacker capability, required conditions, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or fuzz/invariant/fork test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt
