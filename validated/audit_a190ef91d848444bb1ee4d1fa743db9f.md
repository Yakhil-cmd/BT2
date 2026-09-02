### Title
Fail-open webhook signature verification (`GitHubApp#verify_webhook_signature`) lets an unauthenticated attacker forge `push` events that drive `PushHandler#process` → `Stack#sync_github` → merge-queue `merge!` - (File: `lib/shipit/github_app.rb`, `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/push_handler.rb`)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever no `webhook_secret` is configured for the target GitHub organization, so `WebhooksController#verify_signature` accepts any request whose `repository.owner.login`/`organization.login` maps to such an org. `PushHandler` then resolves stacks purely from the (attacker-supplied) `repository.full_name` in the payload and calls `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on the given branch, with no independent proof that the request originated from GitHub.

### Finding Description
The broken binding is: `verify_signature passing == request originated from GitHub for that repository`. In code, `verify_webhook_signature` at [1](#0-0)  short-circuits with `return true unless webhook_secret`, so for any organization configured without a `webhook_secret`, the equality collapses: any POST body, regardless of authenticity, is treated as "verified."

`WebhooksController#verify_signature` derives the organization to check purely from attacker-controlled JSON: [2](#0-1)  and [3](#0-2) . Once past this gate, `PushHandler#process` resolves the target stacks solely from `payload.dig('repository', 'full_name')` (via `Handler#stacks`, [4](#0-3) ) and the `ref`/`after` fields, then calls `sync_github` for every matching, non-archived stack: [5](#0-4) .

Exploit flow: attacker sends `POST /webhooks` with header `X-Github-Event: push` and a JSON body naming a real `repository.full_name`/`owner.login` that belongs to an org configured in Shipit without a `webhook_secret`. `verify_webhook_signature` returns `true` for that org regardless of the (even absent/garbage) `X-Hub-Signature` header, so the forged event is processed as authentic, and `sync_github` is invoked with attacker-chosen `params.after`.

However, `sync_github`/the resulting `GithubSyncJob` pulls actual branch/commit state from GitHub's API using the app's own credentials rather than trusting commit content from the payload itself — the forged webhook can only force/trigger a sync, it does not let the attacker inject commits that don't already exist on the real GitHub repository. Consequently, real amplification (merge queue advancing to a "green head" and `merge!` firing) still depends on the actual state of the real GitHub repository/branch, which the attacker only controls if they already have legitimate push access to that specific repository — a precondition where forging the webhook grants no capability beyond what a genuine push from that same attacker would already trigger. For any repository/org the attacker does not control, the forged push cannot fabricate commits or CI status; it can only cause a premature/duplicate sync.

### Impact Explanation
The concrete violation is authentication bypass at the webhook-signature layer: `WebhooksController#verify_signature` accepts a forged `push` payload for any org lacking a configured `webhook_secret`, letting an unauthenticated attacker trigger `sync_github` (a real state-changing/background job) against stacks belonging to a repository the request never actually originated from. This matches the Critical category "authentication bypass (forged webhook ... accepted)". However, the stronger claim in the question — that this alone drives an *unauthorized merge of attacker-controlled code* — is not established: `sync_github`/`GithubSyncJob` sources commit and status data from GitHub's real API, so the merge-queue amplification only materializes if the attacker already has legitimate push access to the affected repository, in which case they could achieve the same outcome via a genuine push, without needing to forge the signature at all.

### Likelihood Explanation
Requires that Shipit operators configure at least one GitHub organization/app without a `webhook_secret` — a real but operator-side misconfiguration, not a secret the attacker needs to possess. Given that precondition, forging the HTTP request costs nothing (no auth token, no signature knowledge needed). But turning this into "unauthorized deploy/rollback/merge of attacker-controlled code" additionally requires the attacker to control the real GitHub repository content backing the targeted stack, which is outside what the forged webhook itself grants.

### Recommendation
- Require `webhook_secret` to be configured for every registered GitHub organization/app and refuse to boot (or reject all webhooks) for orgs missing one, rather than defaulting to `verify_webhook_signature` returning `true`.
- Alternatively/additionally, re-validate handler side-effects (e.g. `PushHandler`) against the actual GitHub API state (fetch the real HEAD of the branch and compare to `params.after`) before enqueuing `sync_github`, rather than trusting the payload plus a possibly-bypassed signature check.

### Proof of Concept
1. In a minitest webhook controller test, configure `Shipit.github_organizations` (or the equivalent app config) so an organization has no `webhook_secret`.
2. `POST /webhooks` with `X-Github-Event: push`, an arbitrary/garbage `X-Hub-Signature`, and a JSON body naming a stack's real `repository.full_name`, `ref`, and `after`.
3. Assert `GitHubApp#verify_webhook_signature(bad_signature, body)` returns `true` for that org — proving the fail-open equality `verified == (secret.present? ? hmac_match : true)` does not hold as an authentication guarantee.
4. Assert `Stack#sync_github` is invoked (e.g. via mocking/expectation on `GithubSyncJob.perform_later`) even though the signature was never actually valid, and additionally assert that the resulting job's commit content is bounded by the actual GitHub API response for that repository (not by attacker-supplied payload fields), to precisely delineate the achievable impact.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
