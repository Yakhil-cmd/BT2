### Title
StatusHandler writes CI status to commits across all repositories regardless of which organization's webhook secret authenticated the request - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
Shipit's webhook signature verification is scoped to the GitHub *organization* named in the payload's `repository.owner.login` field, but `StatusHandler` (and the commit lookup it uses) never re-checks that the authenticated organization/repository actually owns the commit being mutated. The `sha` field, which selects the target `Commit` record globally across the whole install, is completely outside the trust boundary established by `verify_webhook_signature`.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to validate against using a field taken straight from the unauthenticated JSON body, before the HMAC check runs: [1](#0-0) [2](#0-1) 

The signature is verified over the entire raw payload using the secret of whatever organization `repository.owner.login` names: [3](#0-2) 

This is fine as an authentication step (it does prove the request was signed by *some* org's webhook secret that Shipit trusts), but the downstream handler for `status` events never binds the *content* of the event to that same, authenticated `repository`/organization. `StatusHandler#process` looks up commits purely by SHA across the entire database: [4](#0-3) 

Unlike other handlers (`PushHandler`, `PullRequest::OpenedHandler`) which resolve the target via `Repository.from_github_repo_name(repository_name)` derived from the same `repository.full_name` field, `StatusHandler` inherits `Handler#stacks`/`#repository_name` but doesn't use them at all — it bypasses the repository scoping entirely and does a bare `Commit.where(sha: params.sha)`: [5](#0-4) 

Because git commit SHAs are effectively global 40-hex identifiers and are frequently identical/known across forks, mirrors, or simply guessable/observable from a public repo, an entity that legitimately controls the webhook secret for **any** organization configured in this Shipit instance (per the documented multi-organization setup) can sign a `status` event whose top-level `repository.owner.login`/`full_name` names their own org (satisfying `verify_webhook_signature`), while the `sha` field references a commit that actually belongs to a **different** stack/repository entirely.

`add_status` then writes a new `Status` record onto that unrelated commit and fires `deployable_status`/`commit_status` hooks and `stack.schedule_merges`: [6](#0-5) [7](#0-6) 

Since `deployable?` and the merge-queue gating are driven by CI status (`success?`, `blocked?`), and `create_status_from_github!` can inject an arbitrary `state`/`context`/`description` for a commit belonging to a stack the attacker's org has no relationship with, this breaks the binding "organization that authenticated versus the repository that is written."

### Impact Explanation
This allows an entity holding only its own org's webhook secret (not the victim stack's GitHub write access, not a Shipit session or `ApiClient` token) to inject fabricated CI status on commits belonging to a completely different repository/stack. If that status satisfies `stack.blocking_statuses`/`required_statuses` gating or flips `deployable?` to true, it can unblock/trigger an unauthorized deploy or merge-queue advancement (`stack.schedule_merges` is invoked directly from `add_status`), which maps to the "unauthorized deploy, rollback or merge" Critical impact category, or at minimum falsifies CI state read across repositories (High: unauthenticated write of stack state it doesn't own).

### Likelihood Explanation
Requires only that the attacker controls (or has been granted) the webhook secret for one organization served by a shared/multi-org Shipit instance — an explicitly documented and supported configuration (`docs/setup.md`, "Using Multiple Github Applications"). No repository write access, GitHub App private key, or Shipit session/API token is needed. The target `sha` need only be known (public commit hashes are trivially observable), making this a straightforward analog to the fuel-vm report's core flaw: a verification step that authenticates one thing (the organization/signature) while the operation acted on covers a different, unchecked field (the commit's actual owning repository).

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository/stack identified by the *same* `repository.full_name`/organization that was cryptographically verified, e.g. `stacks.commits.where(sha: params.sha)` (mirroring `PushHandler`'s use of `stacks`), rather than a global `Commit.where(sha:)` lookup. More generally, every handler should derive the affected `Stack`/`Repository` exclusively from the field that was authenticated by `verify_webhook_signature`, and reject events where the commit's actual `stack.repository` does not match the verified `repository_owner`.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `victim-org` and `attacker-org` (per the documented multi-org `github:` config), each with its own `webhook_secret`.
2. As a user who administers `attacker-org`'s GitHub App (but has no access to `victim-org`), obtain `attacker-org`'s `webhook_secret`.
3. Discover/guess a commit SHA belonging to a stack under `victim-org` (e.g. from a public repo, PR, or prior visible deploy).
4. Craft a `status` webhook payload: `{"sha": "<victim-sha>", "state": "success", "context": "ci/attacker", "repository": {"full_name": "attacker-org/some-repo", "owner": {"login": "attacker-org"}}}`.
5. Sign it with `attacker-org`'s `webhook_secret` via HMAC-SHA1 as `X-Hub-Signature`, and POST it to `/webhooks` with `X-Github-Event: status`.
6. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature (`app/controllers/shipit/webhooks_controller.rb:24-30`, `lib/shipit/github_app.rb:76-83`).
7. `StatusHandler#process` executes `Commit.where(sha: "<victim-sha>")`, finds the commit belonging to the victim's stack, and calls `create_status_from_github!`, injecting a forged `success` status onto a commit the attacker never had access to (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`, `app/models/shipit/commit.rb:165-169`), potentially unblocking deploy/merge gating on the victim stack.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
