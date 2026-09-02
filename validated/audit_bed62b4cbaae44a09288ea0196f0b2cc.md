### Title
Cross-tenant `check_suite` forgery via `repository_owner`/`repository.full_name` divergence enables unauthorized stack mutation - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` picks the HMAC secret to validate the webhook using `repository_owner`, which falls back from `repository.owner.login` to the independent `organization.login` field. `Handler#repository_name` (used by every event handler, including `CheckSuiteHandler`) instead reads `repository.full_name` directly, with no cross-check against the identity used for signature verification. An attacker who legitimately controls a webhook secret for one configured GitHub organization/repo in the Shipit instance can therefore sign a payload as themselves while pointing `repository.full_name` at a victim repository, causing the victim's stack to be acted upon.

### Finding Description
The broken binding is the implicit equality the code assumes but never enforces:
`repository_owner` (used in `verify_signature` to pick the webhook secret) == owner of `repository.full_name` (used by `Handler#repository_name`/`stacks`).

Trace:
- `WebhooksController#repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`): `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`.
- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) calls `Shipit.github(organization: repository_owner)` and validates `X-Hub-Signature` against that organization's configured `webhook_secret` [1](#0-0) [2](#0-1) .
- `Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) reads `payload.dig('repository', 'full_name')` directly, independent of `repository_owner`, and `stacks` (line 32-34) resolves `Repository.from_github_repo_name(repository_name)` to select which stacks the handler will act upon [3](#0-2) .
- `CheckSuiteHandler#process` uses `stacks.where(branch: params.check_suite.head_branch)` and reschedules `schedule_refresh_check_runs!` for matching commits [4](#0-3) .

Exploit flow: An attacker who legitimately owns/administers a repository already onboarded to the same Shipit instance (and therefore knows the `webhook_secret` configured for their own organization) crafts a `check_suite` payload where `repository` contains `full_name: "victim-org/victim-repo"` but omits `repository.owner.login`, and includes a top-level `organization: { login: "attacker-org" }`. `repository_owner` resolves to `attacker-org`, so `verify_signature` validates the HMAC using the attacker's own known secret — which succeeds because the attacker signed it correctly. The request passes signature verification entirely under the attacker's own tenant identity. `CheckSuiteHandler`, however, resolves the target stack using `repository.full_name`, which points at the victim's repository, and reschedules check-run refresh on the victim's commits matching the attacker-chosen `head_sha`/`head_branch`.

Existing guards do not stop this: `verify_signature` only ensures *some* organization's secret matches, not that the identity used for verification matches the identity acted upon; `drop_unhandled_event` and `ExplicitParameters` schema only enforce presence/type of `check_suite.head_sha`/`head_branch`, not repository identity consistency; there is no `require_permission!`/`authorized?` check in the webhook path since it is intentionally unauthenticated and keyed only by HMAC.

### Impact Explanation
The attacker can cause writes (`schedule_refresh_check_runs!` job enqueuing) against commits/stacks belonging to a repository they never authenticated for, using only the trust established by their own tenant's webhook secret. This matches the rule's Critical category "a payload for one repository mutating another's stack, commit, task or team." Whether this cascades into an actual unauthorized deploy depends on downstream logic (e.g., merge-queue/auto-deploy status observers reacting to refreshed check runs) that is out of scope of this specific file trio, but the direct, provable impact — an unauthenticated write against a victim's commit/stack state triggered by a forged cross-tenant signature — is itself a confirmed boundary violation. The `bot_login` amplification claim in the question (that resulting deploys run as the bot identity) is plausible given `bot_login` config elsewhere, but the concrete artifact demonstrable purely within these three files is the check-run refresh scheduling on the victim's commit, not an outright deploy trigger. Blast radius is any repository configured on the same multi-tenant Shipit instance, from any single onboarded tenant.

### Likelihood Explanation
Requires: (a) a multi-tenant Shipit deployment serving more than one GitHub organization/repository, each with a distinct configured `webhook_secret`; (b) the attacker legitimately controls at least one such organization/repo already onboarded to Shipit (so they know that org's secret, as they set up the GitHub webhook themselves); (c) knowledge of the victim's exact `full_name` and existence of a matching branch/commit on the victim's stack (both are typically public/discoverable). Attacker cost is a single crafted HTTP POST with a valid HMAC computed from their own known secret. This is fully repeatable against any victim repository hosted on the same Shipit instance.

### Recommendation
Enforce a single source of truth for repository identity across signature verification and handler dispatch: derive `repository_owner` and `repository_name` from the exact same `repository` object (not `organization`), and reject the event if `repository` is missing required owner/full_name fields rather than falling back silently to `organization.login`. Additionally, `Handler#repository_name`/`stacks` should be resolved once at the controller level (post-verification) using the same repository object used for signature selection, and passed into handlers, rather than each handler independently re-reading `payload['repository']`.

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb` (or a new handler test), under "organization fallback selection":
1. Configure two orgs in `Shipit.github_configs`-equivalent test setup: `attacker-org` (with known `webhook_secret_a`) and `victim-org/victim-repo` (registered stack `victim-org/victim-repo` on branch `master`, with a known `commit.sha`).
2. Build payload:
```ruby
payload = {
  'action' => 'completed',
  'repository' => { 'full_name' => 'victim-org/victim-repo' }, # no owner.login
  'organization' => { 'login' => 'attacker-org' },
  'check_suite' => { 'head_sha' => victim_commit.sha, 'head_branch' => 'master' }
}.to_json
signature = "sha1=" + OpenSSL::HMAC.hexdigest('sha1', 'webhook_secret_a', payload)
```
3. POST to `/webhooks` with `X-Github-Event: check_suite` and `X-Hub-Signature: signature`.
4. Assert response is `200 OK` (signature accepted under `attacker-org`'s secret — proving `repository_owner == 'attacker-org'` while `repository.full_name == 'victim-org/victim-repo'` diverge and are never cross-checked).
5. Assert `victim_commit.reload` has a scheduled/refreshed check-run job (e.g., assert enqueued job for `schedule_refresh_check_runs!` on `victim_commit`), proving the victim's stack/commit was mutated by a payload authenticated under an unrelated tenant's secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
