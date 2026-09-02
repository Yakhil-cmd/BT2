### Title
Cross-tenant CI status forgery via webhook organization/repository binding mismatch - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
On a multi-organization Shipit deployment (one GitHub App per organization, each with its own `webhook_secret`, as documented in `config/secrets.development.shopify.yml`), the webhook signature is verified against the organization named inside the *unverified* JSON body, but the handler that mutates commit state (`StatusHandler`) never re-checks that the event actually belongs to that organization's repository. An operator of *any* configured organization on the shared instance can therefore forge a `status` webhook — signed with their own legitimately-known `webhook_secret` — that targets a commit belonging to a completely unrelated tenant's stack, injecting arbitrary CI status.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/secret to validate the HMAC against purely from payload-controlled fields: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the same request body whose authenticity is being checked, i.e. `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. The signature therefore only proves "this body was signed with organization X's secret" — it proves nothing about which repository/commit the body's other fields refer to.

`StatusHandler`, which is dispatched once the signature check for organization X passes, resolves its target purely by SHA, with **no repository or organization scoping at all**: [3](#0-2) 

Compare this with `Handler#stacks`/`Handler#repository_name`, which *does* scope lookups by `payload.dig('repository', 'full_name')` in other handlers such as `PushHandler`, but that scoping is likewise never cross-checked against the organization that produced the valid signature: [4](#0-3) [5](#0-4) 

The exploitable equality broken is:
`organization whose webhook_secret authenticated the signature` ≠ `repository/commit that the handler code actually writes to`.

Because Shipit explicitly supports hosting several independent GitHub organizations behind one instance (`Shipit.github(organization: ...)`, multi-key `github:` config in `config/secrets.development.shopify.yml`, `lib/shipit/github_app.rb`), each tenant organization legitimately possesses its own `webhook_secret` (chosen by that org's own admin when creating their GitHub App, per `docs/setup.md`). That secret is not a privileged credential with respect to *other* tenants — yet it is sufficient to sign a forged `X-Hub-Signature` for a payload whose `sha`/`state`/`context` target a commit belonging to another tenant's stack, since `verify_signature` never binds the signature to the specific repository the body claims to describe, and `StatusHandler` never re-derives/validates repository ownership of the SHA it operates on.

### Impact Explanation
An attacker who is merely the legitimate owner/admin of one tenant organization on a shared multi-org Shipit instance can forge `commit_status`-influencing webhook deliveries for a commit belonging to a different tenant's stack, since `Commit.where(sha: params.sha)` is unscoped by repository/organization. This lets the attacker call `commit.create_status_from_github!` on a victim commit, injecting a fabricated CI status (e.g. `state: "success"`, matching a `required_statuses`/`blocking_statuses` context configured in the victim's `deploy_spec.rb`). Because `Stack#trigger_deploy`/`Commit#deployable?` gate deploys on these very statuses, this can be used to unblock or unlock an otherwise CI-gated deploy on a victim's stack — an unauthorized deploy, matching the High-impact category ("escalation ... or an unauthorized deploy").

### Likelihood Explanation
Medium: it requires the shared Shipit instance to be configured for multiple GitHub organizations (a documented, supported configuration — `config/secrets.development.shopify.yml`), and it requires knowledge of a target commit SHA, which is public GitHub information for the target repo. No access to the victim's `webhook_secret`, `ApiClient` token, or Shipit session is required — only the attacker's own, legitimately-held organization webhook secret.

### Recommendation
Bind the verified signature to the specific repository being acted upon, not just to the organization: after `verify_webhook_signature` succeeds for `repository_owner`, also verify that `repository.full_name`'s owner matches `repository_owner`/the authenticated GitHub App's organization, and reject the request otherwise. Additionally, scope `StatusHandler` (and any other handler that looks up state by SHA/ID alone) through `Repository.from_github_repo_name(repository_name)`/`stacks`, so cross-repository commit lookups are impossible even if the organization check were bypassed.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `orgX` (attacker-controlled) and `victim-org`, each with its own `webhook_secret` as in `config/secrets.development.shopify.yml`.
2. Attacker, who legitimately knows `orgX`'s `webhook_secret`, obtains the SHA of a commit in `victim-org/victim-repo` that is tracked by a Shipit stack (public GitHub data).
3. Attacker crafts a JSON body:
   ```json
   {
     "repository": {"owner": {"login": "orgX"}, "full_name": "orgX/irrelevant"},
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "<required-status-context>"
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(orgX_webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` succeeds because it only checks `orgX`'s secret against `repository_owner == "orgX"` [1](#0-0) .
6. `StatusHandler#process` matches `Commit.where(sha: params.sha)` against the victim's actual commit, regardless of the `repository` field, and creates a forged successful status on it [3](#0-2) .

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
