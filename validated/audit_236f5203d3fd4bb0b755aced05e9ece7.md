### Title
Webhook organization used to select the HMAC secret is not bound to the repository/commit the event handlers act on, allowing cross-organization status/event forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` derives which GitHub organization's webhook secret to use for HMAC verification directly from attacker-controlled JSON fields in the same payload it is verifying, while the handlers that actually act on the payload (in particular `StatusHandler`, and to a lesser extent `PushHandler`) key off a *different* field of that payload (or no repository field at all) that is never cross-checked against the field used to pick the verification secret.

### Finding Description
`verify_signature` picks the GitHub App/secret to verify against using: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the untrusted, attacker-supplied JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). This value selects which org's `webhook_secret` (`Shipit.github(organization: repository_owner)`) is used to validate `X-Hub-Signature` via `verify_webhook_signature`, which is a pure `HMAC-SHA1(secret, raw_body)` comparison: [3](#0-2) 

Because HMAC verification only proves "this body was signed with organization X's secret," and organization X is itself chosen from a field inside that same body, an operator who legitimately controls **any one** configured organization in a multi-tenant Shipit deployment (`Shipit.github_organizations`) knows that organization's real `webhook_secret` and can therefore produce a validly-signed request for **any payload content** they like, as long as `repository.owner.login` (or `organization.login`) names their own org.

The event handlers, however, do not re-validate that the rest of the payload actually belongs to that same organization:

- `StatusHandler#process` matches purely by commit SHA, with no repository/organization scoping at all: [4](#0-3) 

- `Handler#repository_name`/`#stacks` (used by `PushHandler`, `CheckSuiteHandler`, etc.) look up the target stack from `payload.dig('repository', 'full_name')`, a field independent from the `repository.owner.login`/`organization.login` field used for signature-secret selection: [5](#0-4) [6](#0-5) 

So an attacker who owns "attacker-org" (a legitimately configured tenant) can sign a `status` event body with `repository.owner.login: "attacker-org"` (so `verify_signature` fetches and matches with the attacker's own known secret) while setting `sha` to a commit belonging to `victim-org`'s stack. `StatusHandler` will happily attach that forged status (arbitrary `state`, `description`, `target_url`, `context`) to the victim's commit, because it never checks which organization/repository owns that commit.

This is the exact analog of the M-6 pattern requested: a field that is *acted on* (`sha` / `repository.full_name`) is never covered by the binding that was actually verified (the organization identity selected from a different, attacker-chosen field).

### Impact Explanation
Shipit supports "blocking statuses" that gate deploys — commits missing or failing required statuses are prevented from being deployed (see CHANGELOG entry on blocking statuses). By forging a `success` status on a victim organization's commit from an unrelated, attacker-controlled organization's signing key, an attacker with no access to the victim org/repo can unblock and enable an **unauthorized deploy** of a commit that never actually passed CI. This matches the Critical impact bucket ("unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires the attacker to control at least one legitimately-configured GitHub organization/App entry in the Shipit multi-tenant `secrets.github` configuration (i.e., know that org's real `webhook_secret`), which is a realistic scenario for any Shipit instance shared across multiple orgs/teams. No access to the victim org's App, private key, or webhook secret is needed, and no Shipit session/API token is required — only the ability to send an HTTP POST to `/github/webhooks` with a validly-signed (using the attacker's own secret) but cross-referenced payload.

### Recommendation
In `WebhooksController#verify_signature`/`Handler`, bind the organization used to select the verification secret to the same field(s) subsequently used to resolve the target repository/stack, and reject requests where they diverge. `StatusHandler` (and any handler that queries records without going through `Handler#stacks`) should scope its lookup (`Commit.where(sha:)`) to commits belonging to the verified organization's repositories only.

### Proof of Concept
1. Attacker registers/operates "attacker-org" as one of the configured organizations in Shipit's multi-tenant `secrets.github` config and knows `attacker-org`'s real `webhook_secret`.
2. Attacker crafts a `status` webhook JSON body:
   ```json
   {
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" },
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/required-check"
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, body)` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` (`app/controllers/shipit/webhooks_controller.rb:25-29`), verification succeeds using the attacker's own secret.
5. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) matches `Commit.where(sha: params.sha)` — the victim's commit — and calls `commit.create_status_from_github!(params)`, attaching the forged `success` status regardless of which org/repo actually owns that commit, potentially unblocking a deploy gated on that status.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
