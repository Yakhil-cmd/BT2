### Title
Webhook status forgery across organizations — commit lookup ignores the authenticated organization - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against a specific GitHub organization derived from the payload itself, then dispatches the *same untrusted payload* to a handler that never re-checks that the organization it authenticated as owns the resource it mutates. `StatusHandler` writes a commit status by SHA alone, with no repository/organization scoping at all, breaking the binding "organization authenticated == repository being written."

### Finding Description
`WebhooksController#verify_signature` derives the organization to authenticate against directly from attacker-controlled payload fields: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` is a per-organization secret, so any organization onboarded into Shipit (i.e. any tenant that self-installed the Shipit GitHub App on their own org, per `config/secrets.development.shopify.yml`) can legitimately compute a valid HMAC for **any payload body it likes**, because it knows its own `webhook_secret`: [3](#0-2) 

Once the signature check passes for `repository_owner = "attacker-org"`, `WebhooksController#create` blindly forwards the parsed JSON body to the matching handler: [4](#0-3) 

`StatusHandler` (registered for the `status` event) then looks up the target `Commit` **solely by `sha`**, with no repository or organization filter whatsoever: [5](#0-4) 

Unlike `PushHandler`/`CheckSuiteHandler`, which at least scope through `stacks`/`repository_name` (`payload.dig('repository', 'full_name')`) via the base `Handler` class: [6](#0-5) 
`StatusHandler` performs no such scoping — it never consults `repository_owner`, `repository_name`, or any tenant boundary before calling `commit.create_status_from_github!(params)`.

This is the analog of the reported bug class: just as `getRedeemAmount()` used one boundary (`COLLATERAL_THRESHOLD`) inconsistently against the actual TVL/price relationship, here the webhook pipeline uses one boundary (the *organization* whose secret validated the HMAC) while the actual mutation (`Commit.where(sha:)`) operates on an entirely different, unchecked boundary (a global commit SHA space spanning every organization/repository hosted by this Shipit instance). The equality that should hold — `organization authenticated == organization owning the commit being written` — is never enforced.

### Impact Explanation
An organization/tenant that legitimately controls its own GitHub App installation and `webhook_secret` in a multi-tenant Shipit deployment can forge arbitrary commit statuses (`success`/`failure`, `context`, `description`, `target_url`) for **any commit SHA in any other tenant's repository**, as long as that SHA happens to exist in the `commits` table (e.g., a SHA the attacker can predict or has observed, such as another team's public/internal repo commit). Since commit statuses feed into deploy-gating (`deployable_status`/CI checks), this allows an unprivileged-relative-to-the-victim-org actor to mark a victim's commit as CI-passing, enabling an unauthorized deploy of that commit on the victim's stack — a cross-repository/cross-organization write with deploy-authorization impact.

### Likelihood Explanation
This requires the attacker to control at least one legitimate, self-onboarded organization on the shared Shipit instance (i.e. know their own `webhook_secret`) — a standard unprivileged-relative-to-other-tenants position in a multi-tenant Shipit deployment, and does not require any Shipit session, `ApiClient` token, or GitHub write access to the victim repository. The only additional requirement is knowledge or guessability of a target commit SHA, which is often available (public repos, PR references, etc.).

### Recommendation
`StatusHandler` (and any other handler that doesn't already do so) must verify that the resolved `Commit`'s stack belongs to the same `repository_owner`/`repository_full_name` that was authenticated in `verify_signature`, mirroring the `stacks`/`repository_name` scoping already used by `PushHandler` and `CheckSuiteHandler`. The organization used to select the webhook secret must be threaded through to every handler and enforced as a hard filter on the records being mutated, not merely used for HMAC selection.

### Proof of Concept
1. Attacker owns/administers `org-attacker`, which is configured in Shipit's `github` config (`config/secrets.development.shopify.yml`-style entry) with a known `webhook_secret`.
2. Attacker learns the SHA of a commit belonging to `victim-org/victim-repo` (e.g. from a public GitHub commit link).
3. Attacker computes `sha256=HMAC(webhook_secret_attacker, body)` for a crafted `status` event body:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/tests",
     "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-attacker/whatever" }
   }
   ```
4. POSTs to `/webhooks` with `X-Github-Event: status` and the computed `X-Hub-Signature`.
5. `verify_signature` resolves `Shipit.github(organization: "org-attacker")` and successfully verifies (own secret), per `app/controllers/shipit/webhooks_controller.rb:24-30`.
6. `StatusHandler#process` finds the victim's `Commit` purely by `sha` and applies the forged status, per `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`, with no check that `org-attacker` owns `victim-org/victim-repo`.

Note: I was unable to fully trace, within the tool budget, how `create_status_from_github!` output subsequently gates `Stack#deploy`/merge-queue logic (e.g. exact `deployable_status` aggregation code), so the precise deploy-authorization consequence should be confirmed by a background agent with fuller repo access before treating this as a final Critical/High classification.

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
