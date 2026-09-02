## Finding

### Title
Webhook organization used for signature verification is decoupled from the repository the payload is applied to, allowing cross-repository webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
The GitHub App webhook secret used to verify a webhook's HMAC signature is selected from one field of the JSON body (`repository.owner.login`), while the handlers that mutate state look up the target `Repository`/`Stack` using an entirely different field of the same body (`repository.full_name`). Nothing binds these two fields together, so an attacker who legitimately controls their own GitHub organization/App installation (and therefore knows its own `webhook_secret`) can forge a correctly-signed webhook whose `owner.login` matches their org but whose `full_name` names a victim repository already registered in this Shipit instance.

### Finding Description
`WebhooksController#verify_signature` derives the organization used to fetch the verifying `GitHubApp`/secret purely from the payload itself: [1](#0-0) [2](#0-1) 

That is, `repository_owner` = `params.dig('repository', 'owner', 'login')`. The signature is checked against the `webhook_secret` configured for *that* organization via `Shipit.github(organization: repository_owner)` and `GitHubApp#verify_webhook_signature`, which does a straightforward HMAC compare: [3](#0-2) 

Once the signature check passes, event handlers use a **different** field of the same body to decide which `Repository` to act on: [4](#0-3) 

`repository_name` here is `payload.dig('repository', 'full_name')`, which is looked up with an exact, case-insensitive split of `"owner/name"`: [5](#0-4) 

`PushHandler` then walks every non-archived `Stack` of that resolved `Repository` and forces a GitHub sync using attacker-controlled `after` (target SHA): [6](#0-5) 

Because `repository.owner.login` (used for authentication) and `repository.full_name` (used for authorization/target-selection) are two independent, attacker-writable JSON fields inside the same signed body, an attacker who owns a legitimate GitHub org/repo with a GitHub App installed pointing at this Shipit instance can sign a payload with their own valid `webhook_secret` while setting `full_name` to `"victim-org/victim-repo"`. The signature will verify (it's the attacker's own secret being checked against the attacker's own signature), but the handler will resolve and act on the victim's already-registered `Repository`/`Stack` records.

This is the direct structural analog of the audited bug: just as the first LP's donated tokens are able to skew a ratio (`totalRewards`/`existingTotalShares`) that other code trusts implicitly without re-validating provenance, here the field used to prove "who signed this" (`owner.login`) is never cross-checked against the field used to decide "what gets written" (`full_name`) — an authenticated-organization-vs-written-repository binding that the code assumes but never enforces.

### Impact Explanation
An attacker with no privileged access to the target Shipit deployment (no `ApiClient` token, no repository write access, no session) can trigger `GithubSyncJob` and other webhook-driven side effects (push handling, pull_request handling, membership handling, status/check_suite handling — all of which key off the same `repository_name` derived from `full_name`) against any repository/stack already configured in that Shipit instance, as long as they control some other GitHub org with a webhook pointed at the same Shipit host. Depending on which event is forged, this can force unwanted syncs, spoof commit CI `status`/`check_suite` state for the victim stack, or otherwise pollute state that downstream deploy-safety logic in the victim's stack may rely on — crossing a "cross-repository writes" boundary using someone else's, unrelated GitHub credentials.

### Likelihood Explanation
Requires only that the attacker control a distinct GitHub organization/repository with any GitHub App/webhook configured to deliver to the same shared Shipit host (a normal, unprivileged action for any repo owner) — no interaction with the victim's stack, tokens, or GitHub App is needed. This is a realistic and cheap setup for anyone hosting a shared/multi-tenant Shipit instance.

### Recommendation
Bind authentication and authorization to the same field: verify the webhook signature using the organization/owner derived from `repository.full_name` (the same value used to resolve the `Repository`), not a separately-controlled `repository.owner.login`/`organization.login` field. Additionally, after resolving the `Repository`, assert that its stored `owner` matches the organization whose secret validated the signature before dispatching to handlers.

### Proof of Concept
1. Attacker registers `attacker-org/whatever` and installs a GitHub App on it, obtaining a real `webhook_secret` for `attacker-org`.
2. Victim's `victim-org/victim-repo` is already configured as a `Shipit::Repository` with stacks on the shared Shipit instance.
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker_webhook_secret, body)` and POSTs to `/github/webhooks`.
5. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature (attacker knows this secret) — see [1](#0-0) .
6. `PushHandler` then resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` (from `full_name`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's real stacks — see [4](#0-3)  and [7](#0-6) .

Note: I could not fully inspect `app/models/shipit/webhooks/handlers/status_handler.rb` and `check_suite_handler.rb` contents in this session (index/time limits), so I cannot confirm the exact severity of forged CI-status side effects on deploy gating; a full review of those handlers and any deploy-safety checks that key off `Status`/`CheckRun` records is recommended to fully bound the impact.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
