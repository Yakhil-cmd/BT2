### Title
Webhook signature verification binds trust to `repository.owner.login`/`organization.login` while event handlers act on the unrelated `repository.full_name` field, enabling cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate an inbound webhook against using `repository_owner`, a value taken from the payload itself (`repository.owner.login` or `organization.login`). Once the HMAC check passes, every registered `Handler` (including `PushHandler`) resolves the `Repository`/`Stack` to mutate using a *different*, unrelated payload field: `repository.full_name`. Nothing ties these two fields together, so a party that legitimately controls one GitHub organization onboarded to this Shipit instance (and therefore knows that organization's `webhook_secret`) can forge a payload that authenticates as their own org while acting on any other repository's stack.

### Finding Description
`verify_signature` picks the secret to check against like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the attacker-controlled JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`), and `Shipit.github(organization: repository_owner)` looks up the `GitHubApp` config (and its `webhook_secret`) for that name. `verify_webhook_signature` then simply checks the HMAC of the *entire raw body* against that secret: [3](#0-2) 

Because the attacker fully composes the raw body themselves (this isn't a MITM of a real GitHub delivery — it's a self-crafted POST), they can pick `repository.owner.login` to equal an organization whose secret they know, sign the entire body correctly with that secret, and independently set `repository.full_name` to reference an entirely different, victim-owned repository.

Once signature verification passes, `Shipit::Webhooks.for_event(event)` handlers run against the raw params: [4](#0-3) 

Every `Handler` resolves the target `Stack` via `repository_name`, which reads `repository.full_name` — a field never checked against `repository.owner.login`/`organization.login`: [5](#0-4) 

`PushHandler`, for example, uses this to look up stacks by branch and enqueue a sync using an attacker-supplied `expected_head_sha`: [6](#0-5) 

This is the same class of bug described in the Morpho report: a boolean/selector field (`isInEMode` ↔ here, "which org's secret authenticates this request") gates trust, but a second, independently-controlled field (`priceSource` ↔ here, `repository.full_name`) is used downstream for the sensitive operation without being bound to the first. Aave/Morpho's fix was to require the selector and the acted-upon value to agree; Shipit has no equivalent cross-check between the org that authenticated the delivery and the repository whose `Stack` is mutated.

### Impact Explanation
Any organization already onboarded to a multi-org Shipit deployment (a legitimate, low-privileged customer of the operator, who only knows their *own* `webhook_secret`) can forge webhook deliveries — `push`, `status`, `check_suite`, `pull_request`, etc. — that are processed as if they originated from GitHub for any *other* repository/stack hosted on the same instance, because the handlers key off `repository.full_name`/`repository.owner.login` inside the body, not off any property tied to which secret validated the request. This lets a single onboarded org inject fabricated events (e.g., synthetic commit statuses via the `status` event, or forced sync/branch-tracking actions via `push`) into stacks it does not own and has no legitimate access to, corrupting state (`Commit`, `Status`, deployability) that downstream authorized operators rely on when deciding to deploy. This crosses the organization-write boundary called out in the rules ("an organization that authenticated versus the repository that is written") and can lead to spoofed CI/deploy-gating state feeding into an unauthorized deploy decision on a victim stack.

### Likelihood Explanation
Requires only that the attacker control (or have knowledge of the webhook secret for) one organization already configured on the shared Shipit instance — no repository write access, no Shipit session, and no GitHub App private key for the victim org. This is exactly the kind of "trust anchor selected by attacker-controlled field, but a different attacker-controlled field is later trusted for the sensitive action" pattern that is straightforward to exploit once discovered, and does not depend on any race condition or unusual configuration beyond the (documented and supported) multi-organization setup.

### Recommendation
After signature verification succeeds, `WebhooksController`/`Handler` should re-derive and enforce that `repository.full_name`'s owner matches the exact organization (`repository_owner`) whose secret validated the signature (i.e., verify `repository.full_name.split('/').first == repository_owner`, or bind the resolved `Stack`'s repository to the same organization used for `Shipit.github(organization: ...)`), rejecting the webhook otherwise — analogous to Morpho's fix of only trusting the alternate price source when it is consistent with, and explicitly gated on, the same e-mode condition.

### Proof of Concept
1. Attacker legitimately administers GitHub org `attacker-org`, which is onboarded to the target Shipit instance with a known `webhook_secret` (`S_attacker`).
2. Attacker crafts a raw JSON body for a `push` event:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker chosen sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(S_attacker, body)` and POSTs it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: 'attacker-org')`, and the HMAC check succeeds because the attacker used the correct secret for `attacker-org`.
5. `PushHandler` (via `Handler#repository_name`) resolves the target using `repository.full_name` = `victim-org/victim-repo`, and enqueues `sync_github(expected_head_sha: params.after)` against the victim's stack — despite the request never being authenticated by or on behalf of `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
