### Title
Webhook signature is verified against `repository.owner.login`'s secret while the write target is resolved from the unrelated `repository.full_name` field, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository.owner.login` from the untrusted JSON body, while `Shipit::Webhooks::Handlers::Handler#stacks` (used by every handler, including `PushHandler`, `StatusHandler`, `CheckSuiteHandler`) resolves the `Repository`/`Stack` to mutate using the separate, independently-attacker-controlled `repository.full_name` field from the same body. Nothing binds these two fields together, so a valid signature computed with organization A's secret can be replayed with a payload whose `repository.full_name` points at a stack belonging to an unrelated organization B.

### Finding Description
The controller picks the verification key by organization: [1](#0-0) 
`repository_owner` is read straight from the payload: [2](#0-1) 

`verify_webhook_signature` only checks the HMAC of the raw body against the secret configured for that organization — it never re-checks that the body's other repository fields are consistent with that organization: [3](#0-2) 

Once the signature passes, every event handler resolves the actual `Stack`/`Repository` to act on from a *different* field of the same body, `repository.full_name`, with no cross-check against `repository.owner.login`: [4](#0-3) 

`PushHandler` uses that same `stacks` helper to trigger a GitHub sync (which can advance the deployed commit for a stack) purely based on `repository.full_name` and `ref`: [5](#0-4) 

This is a direct analog of the Ethos bug class: the check that authenticates one identity (`repository.owner.login`, whose secret is used to authorize the request) is not the same identity that ultimately gets acted upon (`repository.full_name`, which selects the `Stack` written to) — i.e. `organization authenticated ≠ repository written`.

### Impact Explanation
Any actor who legitimately administers a Shipit-tracked GitHub organization/App (and therefore knows that organization's `webhook_secret`, which is standard, non-privileged knowledge for a repo/org owner configuring their own webhook) can forge a webhook whose signature is valid for *their own* organization but whose `repository.full_name` names a stack belonging to a completely different, unrelated organization tracked by the same Shipit instance. This lets the attacker:
- Trigger `GithubSyncJob` on a victim stack via `push` events, advancing/altering the recorded head commit tracked for deploys.
- Inject fabricated `status`/`check_suite` results (via `StatusHandler`/`CheckSuiteHandler`, which inherit the same unchecked `stacks` resolution) for a victim's commits, which can influence merge/deploy gating logic that depends on commit statuses.

This crosses an organizational trust boundary that Shipit explicitly relies on (`Shipit.github(organization:)` picking a distinct secret per org specifically so one org cannot act on another's data), resulting in cross-repository/cross-organization writes and potentially an unauthorized deploy — matching the "cross-repository writes / unauthorized deploy" Critical impact category.

### Likelihood Explanation
Requires only that the attacker administers (or has been given webhook configuration access to) any single organization/repository that is itself already onboarded to the same Shipit instance — a bar far lower than compromising Shipit session/API credentials. Since the vulnerable code path (`Handler#stacks`) is shared by all webhook handlers, the blast radius covers push, status, and check_suite processing uniformly.

### Recommendation
Require that `repository.full_name`'s owner segment matches the `repository.owner.login` (or `organization.login`) used to select the verification secret, rejecting the webhook otherwise. Alternatively, resolve the target `Repository`/`Stack` scoped to the same organization key that was used for signature verification, rather than trusting an independent field of the payload.

### Proof of Concept
1. Attacker controls org `attacker-org`, which is legitimately installed on the same Shipit instance and therefore knows `attacker-org`'s `webhook_secret`.
2. Attacker crafts a `push` payload where `repository.owner.login = "attacker-org"` but `repository.full_name = "victim-org/victim-repo"` (an existing Shipit-tracked stack).
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s `webhook_secret` over this exact body per `GitHubApp#verify_webhook_signature` [3](#0-2) .
4. `WebhooksController#verify_signature` looks up `Shipit.github(organization: "attacker-org")` and successfully verifies the forged signature [1](#0-0) .
5. `PushHandler#process` resolves `stacks` via `repository.full_name = "victim-org/victim-repo"` [4](#0-3)  and calls `stack.sync_github` on the victim's stack [6](#0-5) , despite the request never having been authenticated for `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
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
```
