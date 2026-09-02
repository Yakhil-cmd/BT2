### Title
Webhook signature verification binds only to the organization inferred from `repository.owner.login`, not to the `repository.full_name` the handlers actually act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* organization's webhook secret to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) out of the attacker-supplied JSON body, then calls `Shipit.github(organization: repository_owner)` to fetch that organization's secret. Every webhook `Handler` subclass, however, determines the repository/stacks it actually mutates via a *different* field of the same body: `payload.dig('repository', 'full_name')`. Nothing ties these two fields together, so a party who legitimately controls (and knows the webhook secret for) one Shipit-configured GitHub organization can forge a webhook whose `repository.owner.login` names their own org (so the signature check passes against a secret they know) while `repository.full_name` names an entirely different, victim repository belonging to another org configured on the same Shipit instance.

### Finding Description
The binding that should hold is:

`organization whose secret authenticated the request == organization that owns the repository the handlers act on`

Before the attacker's forged request, for any legitimately-delivered webhook these two are always equal, because GitHub itself sets `repository.owner.login` and `repository.full_name` consistently.

`verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` resolves the signing organization purely from payload content: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` only checks that the HMAC over the raw body matches the secret for *that* organization; it says nothing about which repository fields inside the body are trustworthy: [3](#0-2) 

Every handler, however, resolves the target repository/stacks independently, from a different JSON field, with no cross-check against the organization used for signature verification: [4](#0-3) 

`Repository.from_github_repo_name` splits that attacker-controlled `full_name` on `/` and looks the row up directly: [5](#0-4) 

So after the attacker's request: the signature is valid (checked against organization A's secret, which the attacker legitimately knows because they administer org A's GitHub App/webhook config), but the repository/stacks acted upon are org B's ("victim") repository — because `full_name` was never checked against `owner.login`, and `owner.login` was never checked against the repository actually being addressed. The equality the code implicitly assumes (`repository.owner.login`'s org == `repository.full_name`'s org) is never enforced, and it is exactly this kind of "field acted on but not covered by the verified binding" mismatch that the Nouns DAO report describes (there: `forVotes`/`canceled` state used for reward eligibility without being tied to the actual final, non-cancelled proposal state).

Concretely, `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) will call `stack.sync_github` on the victim repo's stacks using the attacker-chosen `after` SHA, and `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) will write a commit status onto the victim repo's commits — for stacks belonging to an organization the attacker never authenticated as.

### Impact Explanation
This lets an attacker who is a legitimate admin/owner of one GitHub organization configured on a shared multi-tenant Shipit instance (i.e., they know that org's `webhook_secret`) forge webhook events that are attributed, signature-wise, to their own org but that operate on another tenant's repository/stacks. Depending on which handler is triggered this allows: injecting fake commits/push events that trigger `sync_github` and deploy-eligibility recalculation on a victim stack (`push`), or writing forged commit statuses (`status`) that can flip a victim commit from "not deployable" to "deployable", potentially unlocking an unauthorized deploy path on the victim's stack. This crosses the "unauthenticated write into another tenant's repository state" boundary and can be a stepping stone to an unauthorized deploy, matching the High-severity impact bar (escalation across repository/stack trust boundaries, enabling an unauthorized ship).

### Likelihood Explanation
Requires the attacker to be a legitimate administrator of at least one GitHub organization/App that is itself configured as a tenant on the same Shipit installation (i.e., they know that org's webhook secret) — this is a real, low-friction precondition on any multi-org Shipit deployment (`Shipit.github_organizations`/`github_app_config`), not a privileged Shipit account or stolen secret. No collusion or capital threshold is needed (unlike the 10%-quorum precondition in the original report), making this comparatively easier to exploit once multi-org config is in use.

### Recommendation
In `verify_signature`, after resolving `repository_owner` and verifying the signature, also verify that `repository_owner` matches the owner segment of `payload.dig('repository', 'full_name')` (and reject if they differ), or better: derive the acting `Repository`/organization strictly from the same field used to select the verifying secret, and have `Handler#repository_name` be constrained to repositories belonging to that verified organization. `lib/shipit/github_app.rb`'s `verify_webhook_signature` should not be the only guard; the controller must also assert that the field driving downstream side effects (`repository.full_name`) is consistent with the field that selected the trusted secret (`repository.owner.login`).

### Proof of Concept
1. Attacker administers GitHub org `attacker-org`, which is registered as a tenant in Shipit's `secrets.github` config with webhook secret `S_A` known to the attacker (they configured the GitHub App/webhook themselves).
2. Victim org `victim-org` is a separate tenant on the same Shipit instance with its own repository `victim-org/victim-repo` and stacks.
3. Attacker crafts a `push` webhook JSON body:
   ```json
   {
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>"
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_A, raw_body)>` using their known secret `S_A` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC check passes (signed with `S_A`) — request is accepted.
6. `PushHandler#process` resolves `stacks` via `Handler#repository_name` → `payload.dig('repository','full_name')` = `"victim-org/victim-repo"`, and calls `stack.sync_github(expected_head_sha: <attacker sha>)` on the victim's stacks, even though the attacker never authenticated with victim-org's secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
