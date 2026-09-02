Found it: `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb`) is the one webhook handler that never scopes its lookup to the repository from which the webhook was verified — it matches purely on `sha` across the entire `Commit` table, breaking the binding "organization/repository whose signature was verified" == "repository whose commit state is written."

### Title
Cross-repository status write via `status` webhook not scoped to the verified repository - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` verifies the HMAC signature using the GitHub App/organization derived from the payload's own `repository.owner.login` field [1](#0-0) . All other handlers (`PushHandler`, `CheckSuiteHandler`) subsequently scope their DB writes to `Repository.from_github_repo_name(repository_name)`'s stacks, i.e., the same repository whose owner/secret was used for verification [2](#0-1) [3](#0-2) . `StatusHandler`, however, ignores `repository_name`/`stacks` entirely and updates **any** `Commit` in the system whose `sha` matches the payload's `sha`, regardless of which repository it belongs to [4](#0-3) .

### Finding Description
The binding that should hold is: `organization/repository authenticated by the webhook signature` == `repository whose commit status is mutated`. `WebhooksController#repository_owner` reads `params.dig('repository','owner','login')` to select which GitHub App/secret verifies the signature [5](#0-4) . Once verified, the payload's `repository` field is used to scope `Handler#stacks` — except in `StatusHandler`, which calls `Commit.where(sha: params.sha)` with no repository filter at all [4](#0-3) .

Since a repository owner (organization admin) legitimately holding install access to their own GitHub App/webhook secret can produce a validly-signed `status` event for their own repository, they can set the `sha` field to any 40-character hex string of their choosing — including the SHA of a commit that actually belongs to a completely different, unrelated repository/stack tracked by the same Shipit instance (SHA collisions across repos are common practice, e.g., identical commits from forks/subtrees, or an attacker simply guesses/observes another stack's known commit SHA from a public Shipit UI or GitHub history). The `sha` field is never validated against the repository that authenticated the request, so the write of `create_status_from_github!` lands on `Commit` rows belonging to a target repository the attacker never had signature authority over.

### Impact Explanation
`Commit#create_status_from_github!` writes/overwrites CI status contexts on the target commit [6](#0-5) . Shipit uses commit statuses to gate deployability (`ci.require`/`blocking` checks feed `deployable?`) and continuous delivery decisions. An attacker who controls a webhook-signing GitHub App for one repository can inject a fabricated "success" status (matching `ci.require`/`blocking` contexts) onto a commit belonging to a different repository/stack, satisfying `Commit#deployable?` there and enabling continuous delivery to trigger an unauthorized deploy of that other stack. This crosses the "unauthorized deploy" impact bar, since the attacker never had write access to, nor a valid signature binding for, the victim repository.

### Likelihood Explanation
Requires the attacker to control (or have been granted) a legitimate, signed webhook channel for at least one repository/organization onboarded to the same Shipit instance — a plausible multi-tenant setup documented in this engine ("Using Multiple Github Applications" / per-org `webhook_secret` config) [7](#0-6) . It additionally requires a known/guessable target `sha` and a matching required-status `context` string, both discoverable via the victim stack's public commit history/UI. This is a realistic but non-trivial multi-tenant scenario, hence not high-likelihood but concretely reachable without any additional credential (no `ApiClient` token, no repo write access to the victim repo).

### Recommendation
Scope `StatusHandler#process` to commits belonging to the verified repository, mirroring `Handler#stacks`/`repository_name`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` (or filter through `Repository.from_github_repo_name(repository_name)`), instead of querying the global `Commit` table by `sha` alone.

### Proof of Concept
1. Onboard/organization `attacker-org` with its own GitHub App and `webhook_secret` on a shared Shipit instance that also tracks stacks for `victim-org/victim-repo`.
2. Observe (via Shipit UI or GitHub) a commit SHA `S` in `victim-org/victim-repo` that is required to have status context `ci/required` to become deployable.
3. Craft a `status` webhook payload: `{"repository": {"owner": {"login": "attacker-org"}}, "sha": "S", "state": "success", "context": "ci/required"}`.
4. Sign it with `attacker-org`'s known `webhook_secret` and POST to `WebhooksController#create` with `X-Github-Event: status`.
5. `verify_signature` succeeds (correct org/secret pairing) [8](#0-7) ; `StatusHandler#process` then matches `Commit.where(sha: 'S')` globally and creates a success status on the victim's commit [4](#0-3) , potentially unblocking a deploy of `victim-org/victim-repo`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
