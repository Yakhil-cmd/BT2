### Title
Cross-tenant `repository.full_name` spoofing bypasses per-organization webhook signature scoping in `CheckSuiteHandler#process` - (File: app/models/shipit/webhooks/handlers/check_suite_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate against using `params.dig('repository', 'owner', 'login')`, while `Handler#stacks` (used by `CheckSuiteHandler#process`) selects the target `Repository`/`Stack` using a completely different field, `payload.dig('repository', 'full_name')`. Because these two fields are never cross-validated, an attacker who controls a repository/organization with a known or absent `webhook_secret` can forge a raw JSON body where `repository.owner.login` names their own org (so signature verification passes) but `repository.full_name` names a victim's repository, causing the victim's stack/commit to be operated on.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:
`params.dig('repository','owner','login') == params.dig('repository','full_name').split('/').first`

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` via `repository_owner` (line 59-62: `params.dig('repository','owner','login') || params.dig('organization','login')`) and picks the GitHub App/secret with `Shipit.github(organization: repository_owner)`. This is the only authentication check performed on the inbound POST.
- `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) instead resolves the target repository via `repository_name` = `payload.dig('repository', 'full_name')`, then `Repository.from_github_repo_name(repository_name)&.stacks`.
- `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`) uses `stacks.where(branch: params.check_suite.head_branch)` and then `stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)`, with no additional check that the authenticated org matches the stack's repository owner.

Since `POST /webhooks` is a public endpoint that accepts an arbitrary raw JSON body (`request.raw_post`) and the signature is an HMAC over that exact body computed with whatever secret corresponds to `repository.owner.login`, an attacker who owns any repo/org configured in Shipit (with a known `webhook_secret`, or an org with none configured such that `verify_webhook_signature` trivially accepts) can freely diverge `repository.owner.login` from `repository.full_name`:

```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "check_suite": {
    "head_branch": "main",
    "head_sha": "<victim commit sha>"
  }
}
```

The attacker signs this body with `attacker-org`'s secret (which they legitimately know because it is their own GitHub App/webhook config), sends it to `POST /webhooks` with `X-Github-Event: check_suite`. `verify_signature` passes because it only checks the signature against `attacker-org`'s secret and that check succeeds. `CheckSuiteHandler#process` then resolves the target stack from `full_name` = `victim-org/victim-repo`, finds the victim's stack on branch `main`, matches the victim's real commit sha, and calls `schedule_refresh_check_runs!` on it — an operation attributable to and scoped for `victim-org` but authenticated only against `attacker-org`'s credentials.

None of the existing guards catch this: `verify_signature` never compares `repository.owner.login` to `repository.full_name`'s owner segment; `drop_unhandled_event` only checks the event type is handled; `ExplicitParameters` schema only validates presence/type of `head_sha`/`head_branch`, not repository consistency; `Repository.from_github_repo_name` performs a straightforward DB lookup with no ownership cross-check.

### Impact Explanation
An attacker with a valid webhook secret for any one organization/repository in Shipit (including one they legitimately administer) can force `RefreshCheckRunsJob`-style processing (`schedule_refresh_check_runs!`) to run against an arbitrary victim stack/commit in a different repository, by naming that victim repository in `repository.full_name` while authenticating with their own org's secret named in `repository.owner.login`. This is a cross-tenant write path: a payload authenticated for one repository (`attacker-org`) causes state changes/queued jobs scoped to another repository's stack and commit (`victim-org`), which matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." The same `stacks.where(branch:)` pattern inherited from `Handler` is shared by other webhook handlers, so any handler relying solely on `Handler#stacks`/`repository_name` for scoping is subject to the same owner/full_name divergence, widening the blast radius beyond just check-suite refreshes. This is repeatable for any branch name/commit sha combination the attacker can guess or observe on the victim's public commit history, against any repository configured in the same Shipit instance.

### Likelihood Explanation
Preconditions: the attacker must control at least one repository/organization already registered in Shipit with a webhook configured (or one with no `webhook_secret` set, if `verify_webhook_signature` accepts unsigned requests for such orgs — confirmed logic exists for org-based secret lookup in `Shipit.github(organization:)`, but the exact zero-secret acceptance behavior of `verify_webhook_signature` in `lib/shipit/github_app.rb` was not fully re-verified in this pass due to tool budget). Given that many Shipit deployments are multi-tenant (multiple orgs/repos sharing one instance), and that the attacker only needs to know a victim's public branch name and a commit sha (both are typically public GitHub information), the attack is low-cost, does not require any GitHub or Shipit credentials belonging to the victim, and is directly reproducible via a single crafted HTTP POST.

### Recommendation
In `WebhooksController` or in `Handler#stacks`, cross-validate that `payload.dig('repository','owner','login')` matches the owner segment parsed from `payload.dig('repository','full_name')` before performing any repository/stack lookup, rejecting the webhook (422) on mismatch. More robustly, derive the authenticated organization once in the controller and pass it explicitly into every `Handler`, then have `Handler#stacks` filter `Repository.from_github_repo_name(repository_name)` further by asserting `repository.owner == authenticated_organization`.

### Proof of Concept
Under `test/controllers/webhooks_controller_test.rb` (or equivalent handler test), construct:
1. Two `Repository` records: `attacker-org/attacker-repo` (webhook_secret known to test/attacker) and `victim-org/victim-repo`, each with a `Stack` on branch `main`.
2. A `Commit` on the victim stack with a known `sha`.
3. A raw JSON body for a `check_suite` event where `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`, `check_suite.head_branch = "main"`, `check_suite.head_sha = <victim commit sha>`.
4. Compute `X-Hub-Signature` using `attacker-org`'s configured `webhook_secret` over that exact raw body.
5. POST to `/webhooks` with `X-Github-Event: check_suite` and the computed signature header.
6. Assert the response is `200 OK` (i.e., `verify_signature` accepted it).
7. Assert `schedule_refresh_check_runs!`/`RefreshCheckRunsJob` was enqueued for the **victim's** commit (e.g., via `assert_enqueued_with(job: Shipit::RefreshCheckRunsJob, args: [victim_commit])` or equivalent), proving that authentication scoped to `attacker-org` produced a mutation against `victim-org`'s stack — demonstrating `repository.owner.login != full_name_owner` yet the request still succeeded against the victim's data.