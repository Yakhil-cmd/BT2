### Title
Cross-repository commit-status forgery via webhook signature/repository binding mismatch - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using the organization derived from the payload (`repository.owner.login` / `organization.login`), but the handler that actually mutates state — `StatusHandler` — never re-checks that binding against the repository/stack it writes to. It looks up commits globally by SHA alone, so a valid signature for *organization A* is sufficient to write a commit status onto *any* commit that happens to share that SHA in *any other* stack/repository configured in the same Shipit instance.

### Finding Description
Signature verification is scoped per-organization: [1](#0-0)  picks the GitHub App/secret using `repository_owner`, which is read straight out of the unauthenticated JSON body before the signature is checked: [2](#0-1) . The signature itself is a plain HMAC over the whole raw body computed with that organization's own `webhook_secret`: [3](#0-2) .

Once verified, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the parsed payload to the relevant handler: [4](#0-3) .

Most handlers correctly re-derive their target scope from `repository.full_name` via the base `Handler#stacks` helper: [5](#0-4) . `StatusHandler`, however, does not use this scoping at all — it looks up commits purely by SHA, across the entire installation: [6](#0-5) .

This reproduces the report's bug class exactly: a field that is *authenticated* (the organization whose secret validated the signature) is decoupled from the field that is actually *acted upon* (the commit/repository whose status record gets overwritten), just as CDP.sol's `update` decoupled the accumulator it verified against from the value it wrote.

### Impact Explanation
In a multi-tenant Shipit deployment (multiple `Shipit.github(organization: ...)` configs, each with its own `webhook_secret`), an attacker who legitimately controls one onboarded GitHub organization — and therefore knows/controls that org's own webhook secret, with no Shipit session, `ApiClient` token, or access to the victim repository — can produce a validly signed `status` event for their own org while setting the payload's `sha` to a commit SHA that coincidentally or intentionally collides with a commit in a completely different stack/repository. `StatusHandler` will happily create a fake CI status (`success`, etc.) on that foreign commit. Since commit statuses gate deploy readiness/merge checks in Shipit, this is a cross-repository write that can contribute to an unauthorized deploy or merge on a stack the attacker has no access to.

### Likelihood Explanation
Exploitation requires only: (1) the attacker's own organization being one of possibly several tenants configured on the same Shipit instance (a normal, documented multi-org deployment), and (2) the ability to know a target commit SHA in another repository (SHAs are 40-hex-char but often observable via public commit history, PR pages, or CI logs — not a secret). No credential belonging to the victim organization, no Shipit session, and no GitHub write access to the victim repo is needed, which satisfies the unprivileged-attacker constraint.

### Recommendation
`StatusHandler#process` (and any other handler that doesn't route through `Handler#stacks`) should scope its lookup to commits belonging to the repository named in the same payload (`payload.dig('repository', 'full_name')`), matching the organization that was cryptographically verified, e.g. filter through `stacks`/`Repository.from_github_repo_name(repository_name)` before touching `Commit` records, instead of a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Attacker administers `org-attacker`, which is legitimately configured in this Shipit instance with its own GitHub App and `webhook_secret_attacker`.
2. Attacker identifies a commit SHA `deadbeef...` that exists in `victim-org/victim-repo`'s tracked stack (e.g., observed from a public PR/CI page).
3. Attacker POSTs to `/webhooks` a `status` event body:
   ```json
   {
     "repository": {"owner": {"login": "org-attacker"}, "full_name": "org-attacker/some-repo"},
     "sha": "deadbeef...",
     "state": "success",
     "context": "ci/required-check"
   }
   ```
   signed with `X-Hub-Signature: sha1=<HMAC(webhook_secret_attacker, body)>`.
4. `verify_signature` selects `org-attacker`'s secret via `repository_owner` and validates successfully: [1](#0-0) .
5. `StatusHandler#process` finds the commit by SHA alone, with no repository check, and creates the forged success status on `victim-org/victim-repo`'s commit: [6](#0-5) .

Note: I could not fully trace how `Shipit.github` resolves multiple simultaneously-configured organizations/secrets (`lib/shipit.rb`) within the available context; this affects only the *number of usable secrets* in a given deployment, not the core scoping flaw in `StatusHandler`, which is independent of how many organizations are configured.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
