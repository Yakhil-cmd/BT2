### Title
Cross-repository forgery of commit statuses via `StatusHandler` bypasses per-organization webhook binding - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController` verifies a GitHub webhook's HMAC signature using the `webhook_secret` configured for the *organization named in the payload* (`repository_owner`), which correctly proves the payload was signed by GitHub for that specific organization/repository. However, `StatusHandler#process` then acts on the `sha` field alone, with no re-validation that the reported repository/stack actually corresponds to the commit being updated.

### Finding Description
The signature check binds "the organization that authenticated" to a webhook secret scoped to that organization: [1](#0-0) [2](#0-1) 

That binding is: `verified_signature ⇔ payload signed by GitHub for organization = repository_owner(payload)`.

But once verification passes, the raw `params` are dispatched to the handler for the event without any additional scoping to the repository that authenticated: [3](#0-2) 

`StatusHandler` only declares `sha` and `state` as required fields — it has no `repository` binding requirement — and then updates **every** `Commit` row across the entire Shipit instance that happens to share that `sha`, regardless of which stack/repository it belongs to: [4](#0-3) 

`Commit#create_status_from_github!` then writes a `Status` scoped only to `stack_id` derived from whatever `Commit` record matched, not from the organization that was actually authenticated by the signature check: [5](#0-4) 

This breaks the intended equality: **organization that authenticated (`repository_owner` used to select the `webhook_secret`) ≠ repository/stack whose `Commit` record is written** (`Commit.where(sha: params.sha)`, unscoped by repository). Since git SHA-1 identifiers are content-addressed and identical commits routinely exist in multiple repositories connected to the same Shipit instance (forks, mirrors, cherry-picks, vendored/shared history, monorepo splits, or an attacker deliberately committing the exact same tree/parent/author/committer/timestamp to make an identical commit object in their own repo), an attacker who controls (or triggers CI in) *any* GitHub organization/repository already configured in this Shipit instance can send a genuinely-signed `status` webhook for a `sha` that also exists as a `Commit` in a different, more privileged stack, and have Shipit record a forged `success`/`failure` status against that unrelated stack's commit.

### Impact Explanation
Commit status/state directly gates deploy eligibility and continuous delivery via `Commit#deployable?` and `Stack#next_expected_commit_to_deploy`: [6](#0-5) 

By forging a `success` status (or clearing a `failure`/`blocking` one) on a shared-sha commit belonging to a victim stack, an attacker can make an otherwise non-deployable commit `deployable?`, enabling continuous delivery or a `require_ci`-gated deploy to proceed — an unauthorized deploy triggered purely through a signature that was valid only for the attacker's own, unrelated repository. This matches the "unauthorized deploy" High-impact category.

### Likelihood Explanation
This requires the attacker to control (or have push/CI access to) at least one repository already onboarded to the target Shipit instance, and to get a commit with an identical SHA-1 into their own repository's history (achievable deliberately: git commit objects are deterministic from tree, parent(s), author, committer, and message/timestamps, so an attacker who can observe or predict the victim commit's exact metadata can reproduce the identical object and push it to their own controlled repo, then trigger a `status` event on it). This is a moderate-effort but concrete path, not requiring any credential theft.

### Recommendation
Scope `StatusHandler` (and any other webhook handler that resolves records by content-hash fields like `sha`) to the repository that was authenticated by `verify_signature`. Concretely, filter `Commit.where(sha: params.sha)` by `stack.repository == payload_repository` (the same `full_name`/owner that `WebhooksController#repository_owner` used to select the `webhook_secret`), rather than matching `sha` globally across all stacks.

### Proof of Concept
1. Attacker controls repository `attacker/repo`, which is a configured Shipit stack (attacker has legitimate CI/push access to it, but not to the victim's stack).
2. Attacker crafts a commit object with identical tree/parent/author/committer/timestamps as a known commit in the victim's repository `victim/repo` (sha `abc123...`), and pushes it into `attacker/repo`'s history (or references it in a way GitHub will accept, e.g., via a shared ancestor/fork).
3. Attacker triggers (e.g., via their own CI, or directly via GitHub's Status API on their own repo) a `status` webhook event for `sha=abc123...`, `state=success`, targeting `attacker/repo`. GitHub signs this payload with `attacker/repo`'s org webhook secret.
4. `WebhooksController#verify_signature` validates the signature correctly for `attacker` organization and passes it through: [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: 'abc123...')`, matching the `Commit` row belonging to `victim/repo`'s stack, and calls `commit.create_status_from_github!(params)`, writing a forged `success` status onto the victim's stack: [7](#0-6) 
6. If the victim stack was waiting on this status (`deployable?` was false due to missing/failing CI), it now becomes deployable, and continuous delivery/deploy proceeds without any legitimate signal from `victim/repo`'s own CI or webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```
