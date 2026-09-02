### Title
Cross-repository `check_suite` targeting via decoupled auth-selector (`organization.login`) and target-selector (`repository.full_name`) - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#repository_owner` selects the `GitHubApp` used for signature verification via `params.dig('repository','owner','login') || params.dig('organization','login')`, while `Handler#repository_name` (used by every handler's `stacks` scope, including `CheckSuiteHandler`) independently reads `payload.dig('repository','full_name')`. Because these two lookups read different sub-fields of an attacker-controlled JSON body, an attacker who owns a repository/org registered with Shipit (and thus knows that org's `webhook_secret`) can sign a payload with their own secret while pointing `repository.full_name` at a victim's repository, causing `CheckSuiteHandler` to act on the victim's stack/commit.

### Finding Description
The broken binding: the code implicitly assumes
`repository_owner (auth selector) == repository.full_name's owner (target selector)`,
but these are populated from independent fields: [1](#0-0) [2](#0-1) 

Path:
1. `WebhooksController#create` parses `request.raw_post` into `params` and dispatches to `Shipit::Webhooks.for_event(event)` handlers, after `verify_signature` runs as a `before_action`. [3](#0-2) 
2. `verify_signature` computes `repository_owner` and fetches `Shipit.github(organization: repository_owner)`, then calls `github_app.verify_webhook_signature(signature, request.raw_post)`, which HMAC-validates against that org's own `webhook_secret`. [4](#0-3) 
3. If the attacker omits `repository.owner.login` (or omits `repository` details it entirely aside from `full_name`) but supplies `organization.login` pointing at their *own* org, `repository_owner` resolves to the attacker's org, and the payload validates against a secret the attacker legitimately possesses (their own webhook secret from their own Shipit-registered repository/org).
4. `CheckSuiteHandler.call(params)` instantiates `Handler#initialize`, which derives `stacks` from `repository_name = payload.dig('repository','full_name')` — an attacker-set field, independent of `repository_owner`. [5](#0-4) 
5. If the attacker sets `repository.full_name` to `"victim-org/victim-repo"`, `Repository.from_github_repo_name(...)` resolves the real victim `Stack`, and `CheckSuiteHandler` matches `stacks.where(branch: params.check_suite.head_branch)` then `stack.commits.where(sha: params.check_suite.head_sha)`, calling `schedule_refresh_check_runs!` → `RefreshCheckRunsJob.perform_later(commit_id: id)` on the victim's `Commit` record. [6](#0-5) 

None of the documented guards prevent this: `drop_unhandled_event` only checks the event type exists in the handler registry; `verify_signature` succeeds because it validates against the attacker's *own* legitimately-known secret, not the victim's; `ExplicitParameters` schema for `CheckSuiteHandler` only requires `check_suite.head_sha`/`head_branch`, and does not constrain or cross-check `repository`/`organization` fields at all.

### Impact Explanation
An attacker who owns any repository/org registered with Shipit (and therefore knows that org's webhook secret) can forge a `check_suite` webhook whose `repository.full_name` names an arbitrary victim repository/stack registered on the same Shipit instance. This causes `CheckSuiteHandler` to enqueue `RefreshCheckRunsJob` against the victim's real `Commit` (matched by exact SHA, or effectively by any SHA the attacker knows exists in the victim's commit history), triggering the job to call the victim stack's own GitHub API credentials (`stack.github_api.check_runs(...)`) and write/update `CheckRun` records for that commit. This is a payload originating from one repository's authenticated context causing writes tied to a different repository/stack that never authenticated the request — a cross-tenant authorization/selection confusion matching the "payload for one repository mutating another's stack/commit" category. The content ultimately written is fetched live from GitHub (not attacker-forged status text), which limits the blast radius to unauthorized job scheduling/refresh-triggering rather than fabricated CI results, but the underlying invariant ("a `check_suite` event only affects the repo whose secret authenticated it") is demonstrably broken and repeatable against any stack on the instance whose full repo name the attacker knows.

### Likelihood Explanation
Preconditions: multi-tenant Shipit deployment where multiple distinct organizations/repos are registered with independent `webhook_secret`s, and the attacker controls at least one such registered repository (satisfying the "unprivileged attacker who owns a repo" model). The attacker must also know the victim's exact `full_name`, a valid `head_branch`, and a commit SHA present in the victim stack — all of which are typically public GitHub metadata for open-source or discoverable repos. No GitHub App private key, `secret_key_base`, or victim `webhook_secret` is required. This is fully repeatable with one HTTP POST per attempt and does not require any live GitHub interaction to demonstrate in a minitest (only local HMAC signing with the attacker/org's own configured secret).

### Recommendation
Bind the signature-verification selector and the handler's target-selector to the same, single source of truth. Concretely: derive `repository_owner` strictly from `repository.full_name`'s owner segment (or require `repository.owner.login` to be present and match `repository.full_name`'s owner) instead of falling back to the independent `organization.login` field; alternatively, after verifying the signature for a given `repository_owner`, re-validate that every handler's `repository_name`/`stacks` resolution belongs to that same verified owner before acting, rejecting the event otherwise.

### Proof of Concept
Minitest plan under `test/controllers/webhooks_controller_test.rb` (or a dedicated test file):
1. Configure two orgs in `Shipit.github` config-fixture: `attacker-org` (secret `S_A`) and `victim-org` (secret `S_V`), with a `victim-org/victim-repo` `Repository`/`Stack` and a `Commit` with `sha: "abc123...", branch: "main"` present.
2. Build payload:
```json
{
  "check_suite": {"head_sha": "abc123...", "head_branch": "main"},
  "repository": {"full_name": "victim-org/victim-repo"},
  "organization": {"login": "attacker-org"}
}
```
   Note `repository.owner.login` is intentionally absent.
3. Compute `X-Hub-Signature` using `S_A` (attacker's own secret) over the raw JSON body.
4. POST to `/webhooks` with header `X-Github-Event: check_suite` and the computed signature.
5. Assert response is `200 OK` (verification passed via `attacker-org`'s secret): equality check `repository_owner == "attacker-org"` while `Handler#repository_name == "victim-org/victim-repo"` — these differ, proving the divergence.
6. Assert `RefreshCheckRunsJob` was enqueued with `commit_id` equal to the victim commit's id (`assert_enqueued_with(job: RefreshCheckRunsJob, args: [{ commit_id: victim_commit.id }])`), demonstrating that a payload authenticated by `attacker-org`'s secret caused a scheduled write/refresh against `victim-org`'s commit — violating the stated invariant.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/commit.rb (L152-154)
```ruby
    def schedule_refresh_check_runs!
      RefreshCheckRunsJob.perform_later(commit_id: id)
    end
```
