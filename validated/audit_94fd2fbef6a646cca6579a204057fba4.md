## Cross-Organization Webhook Forgery via Owner/Full-Name Field Mismatch - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret used to authenticate an inbound webhook based on `repository.owner.login` (or `organization.login`), but every event `Handler` resolves the `Stack`/`Repository` it actually mutates using a *different* field in the same attacker-controlled JSON body: `repository.full_name`. Because the HMAC only proves "the sender knows organization X's `webhook_secret`", not "the payload's `repository.full_name` belongs to organization X", any GitHub organization onboarded to this Shipit instance (with its own app_id/installation_id/webhook_secret entry, per the documented multi-org setup) can forge a signed webhook whose `repository.owner.login` is its own org, while `repository.full_name` points at a `Stack` belonging to a completely different, unrelated organization.

### Finding Description
`verify_signature` derives the signing organization purely from the payload, then verifies the raw body against that organization's secret: [1](#0-0) [2](#0-1) 

The `repository_owner` value only gates *which secret* is used for `verify_webhook_signature`, computed in `GitHubApp#verify_webhook_signature`: [3](#0-2) 

Passing that check only proves knowledge of the secret tied to `repository.owner.login` — it says nothing about which repository the rest of the payload refers to. Every handler, however, looks up the target `Stack` from an entirely separate field, `repository.full_name`: [4](#0-3) 

For example, `PushHandler` uses that `stacks` scope (keyed off `full_name`) to trigger a GitHub sync for every matching, non-archived stack: [5](#0-4) 

Since the HMAC signature is computed over the entire raw JSON body, an attacker cannot alter `full_name` in a *real* GitHub-sent webhook without invalidating the signature. But this is a self-service, generic HTTP endpoint (`WebhooksController#create`) that accepts any POST with a valid `X-Hub-Signature`; the attacker does not need GitHub to send it. If the attacker administers their own legitimately-onboarded GitHub organization/app (as documented for multi-org installs), they know that organization's `webhook_secret` and can freely construct any JSON body — including a `repository.full_name` referencing a stack that belongs to a *different* onboarded organization — and sign it themselves. `verify_signature` will pick the attacker's own org secret (via `repository.owner.login`) and pass, while the handler acts on the victim organization's repository (`repository.full_name`).

This breaks the binding: **organization authenticated by the signature ≠ repository actually written by the handler.**

### Impact Explanation
A forged `push` event lets the attacker trigger `Stack#sync_github` against any other tenant's stack in the same Shipit instance, and a forged `status`/`check_suite` event lets the attacker inject fabricated commit statuses/check-runs for arbitrary commits on a foreign repository via `StatusHandler`/`CheckSuiteHandler` (same `stacks` resolution path). Since commit/check status state is used to gate deployability, this enables cross-repository, cross-tenant writes and can be leveraged to make an otherwise non-deployable commit on another organization's stack appear deployable — matching the "cross-repository writes" / "unauthorized deploy" Critical criteria.

### Likelihood Explanation
Exploitability requires the attacker to control any one legitimately onboarded GitHub organization on the multi-org Shipit deployment (i.e., possess that org's `webhook_secret`, which is standard for any tenant/team allowed to register their own repos), and to send a raw HTTP POST with a self-computed signature rather than relying on GitHub's own delivery. No Shipit session, `ApiClient` token, or repository write access on the *victim* repo is needed — only administrative control of one's own onboarded org's webhook configuration, which is a much lower trust boundary than what should be required to write to another tenant's stack.

### Recommendation
Bind repository/organization identity consistently: derive the acting `Stack`/`Repository` scope from the *same* field used to select the verification secret (e.g., resolve stacks only within `repository.owner.login`'s known organization, or reject payloads where `repository.full_name`'s owner segment doesn't match the verified `repository.owner.login`/`organization.login`). Alternatively, verify the signature per-repository/stack (using a secret scoped to the specific `Repository` record) instead of a single secret shared across an entire GitHub organization.

### Proof of Concept
1. Attacker controls `attacker-org`, an organization configured in Shipit's multi-org `secrets.yml` with its own `webhook_secret` `S_A` (per `docs/setup.md`'s "Using Multiple Github Applications" — out-of-scope doc, only cited for confirming the multi-org secret design is intentional and used by `Shipit.github(organization:)`).
2. Attacker crafts a `push` JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-controlled sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S_A, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies using `S_A` [6](#0-5) .
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` [4](#0-3)  and invokes `sync_github(expected_head_sha: params.after)` on the victim's stack, with a signature that only ever proved control of `attacker-org`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
