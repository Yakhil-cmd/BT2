## Analysis

I found a valid analog. The bug class from the report — a `transferFrom` return value returning `false`/`bool` for one field while an `assert`/accounting invariant is checked on a different, unlinked field — maps to a binding break explicitly listed in scope: **"an organization that authenticated versus the repository that is written."**

### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login`, but event handlers act on the unrelated, unverified `repository.full_name` / global `sha` fields - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which configured GitHub App/`webhook_secret` to verify the HMAC against using `repository_owner`, defined as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. But the handler that actually executes the webhook's side effects (`create` → `Shipit::Webhooks.for_event(event)`) resolves the target repository/stack from a **different, unverified-as-linked field**: `payload.dig('repository', 'full_name')` in `Handler#repository_name`, or in `StatusHandler`, from a global `Commit.where(sha: params.sha)` lookup with no repository scoping at all.

### Finding Description [1](#0-0) 
selects the trust anchor (`github_app`/`webhook_secret`) using `repository_owner`: [2](#0-1) 

The signature check only proves the request was signed with *some* organization's configured `webhook_secret` that matches the `owner.login`/`organization.login` value in the JSON body — both of which are attacker-supplied fields inside the very payload being signed. Nothing binds that verified organization to the repository the handlers subsequently act on.

`create` then dispatches the same raw payload to handlers: [3](#0-2) 

`Handler#stacks`/`#repository_name` resolves the target purely from `repository.full_name`: [4](#0-3) 

`PushHandler` uses that to sync/trigger a stack: [5](#0-4) 

Even more direct: `StatusHandler` does not scope by repository at all — it updates commit status by `sha` globally across the entire Shipit instance: [6](#0-5) 

**Break as an equality:** The invariant the engine implicitly relies on is `verified_org(webhook_secret) == owning_org(repository.full_name)`. Nothing enforces this. An attacker who controls a legitimate, Shipit-configured GitHub organization (i.e., they know their own org's `webhook_secret`, a normal condition documented for multi-org setups) can sign a payload with their own org's secret while setting `repository.full_name` (or simply `sha`, for the status event) to point at a completely unrelated stack/commit belonging to a different organization tracked by the same Shipit instance.

Multi-org configuration is a documented, first-class deployment mode: [7](#0-6) 

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary explicitly in scope. Concretely:
- Via forged `push` events: an attacker signs with their own org's `webhook_secret` but sets `repository.full_name` to a victim repo, causing `stack.sync_github` to run against a stack they don't own — cross-organization interference with an unrelated stack's sync/deploy pipeline.
- Via forged `status` events (most severe): `StatusHandler` performs no repository scoping whatsoever — `Commit.where(sha: params.sha)` — so an attacker with any valid org signature can inject a fabricated commit status (e.g., forcing `state: "success"`) for an arbitrary commit SHA belonging to any other tracked stack, independent of which organization authenticated the request. Since commit statuses gate deploy/merge safety checks in Shipit, this can enable an **unauthorized deploy** on a stack the attacker has no legitimate access to — matching the in-scope Critical impact category.

### Likelihood Explanation
Requires the attacker to control (know the `webhook_secret` of) at least one GitHub organization that a shared/multi-tenant Shipit instance has configured — a normal, unprivileged condition for any org owner in a multi-org Shipit deployment, and does not require a Shipit session, API token, or GitHub write access to the victim's repository. This is a realistic configuration per `docs/setup.md`'s own multi-org guidance.

### Recommendation
Bind the verified webhook signature to the specific repository/organization it authorizes, not just to whichever `owner.login`/`organization.login` appears in the unauthenticated JSON body used to pick the secret. Concretely: after verifying the signature with the org determined from the payload, re-derive the owning organization of the *actual acted-upon* target (`repository.full_name` for push/pull_request/check_suite, or the repository owning the `Commit` for status) and reject the event if it doesn't match the organization whose secret produced a valid signature. For `StatusHandler`, scope the `Commit` lookup by repository/stack derived from the verified organization instead of a bare global `sha` match.

### Proof of Concept
1. Shipit is configured (per `docs/setup.md`, "Using Multiple Github Applications") with two orgs: `attacker-org` (attacker knows its `webhook_secret`) and `victim-org/victim-repo` (a stack tracked by the same instance, unrelated to `attacker-org`).
2. Attacker crafts a `status` event JSON body:
   `{"sha": "<victim-commit-sha>", "state": "success", "repository": {"owner": {"login": "attacker-org"}}}`
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker-org's webhook_secret, body)` — this is valid per [8](#0-7) .
4. POST to `/webhooks` with `X-Github-Event: status`. `verify_signature` resolves `repository_owner` = `attacker-org`, looks up `attacker-org`'s app, and the signature verifies successfully (`head(422)` is never triggered).
5. `create` dispatches to `StatusHandler`, which runs `Commit.where(sha: "<victim-commit-sha>")...create_status_from_github!(params)` — with no check that `victim-commit-sha` belongs to `attacker-org`'s repositories — forging a "success" status on the victim's stack/commit, usable to bypass status-gated deploy/merge checks.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
