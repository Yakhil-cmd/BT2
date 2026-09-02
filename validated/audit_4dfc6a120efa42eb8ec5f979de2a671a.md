### Title
Webhook signature is verified against the `repository.owner.login` (or `organization.login`) organization, but handlers act on unrelated payload fields (`repository.full_name`, or nothing at all) — allowing cross-repository/cross-tenant forged pushes and CI statuses ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to HMAC-verify a payload against using only `repository.owner.login` (falling back to `organization.login`) [1](#0-0) [2](#0-1) . Once the HMAC checks out, the raw JSON is dispatched to handlers, which derive the actual write target from a *different* field — `repository.full_name` for the base `Handler#stacks` helper used by `PushHandler` [3](#0-2) [4](#0-3) , or nothing repository-scoped at all for `StatusHandler`, which matches purely by commit SHA across the entire database [5](#0-4) . Nothing cross-checks that `repository.full_name`'s owner segment equals the `repository.owner.login`/`organization.login` value that was actually used to select and verify the signing secret.

### Finding Description
The equality this design implicitly assumes is:

```
organization authenticated by verify_signature (repository.owner.login) == repository actually mutated by the handler (repository.full_name's owner / matched commit's stack)
```

That equality is never enforced. `verify_signature` picks the `GithubApp` instance via `Shipit.github(organization: repository_owner)` [6](#0-5)  where `repository_owner` reads `params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) . The HMAC (`X-Hub-Signature`) is checked against that org's `webhook_secret` via `verify_webhook_signature` [7](#0-6) .

After verification succeeds, `Shipit::Webhooks.for_event(event)` handlers are invoked with the full raw JSON [8](#0-7) :

- `Handler#stacks` (used by `PushHandler`) resolves the target repository from `payload.dig('repository', 'full_name')` [3](#0-2)  — an independent JSON field from `repository.owner.login`, and never checked for consistency with it. An attacker who can produce a valid HMAC for *any* organization the Shipit instance is configured for (e.g. their own onboarded org, or any org whose `webhook_secret` happens to be unset — `verify_webhook_signature` returns `true` unconditionally when no secret is configured [9](#0-8) ) can set `repository.owner.login` to that org (to pass verification) while setting `repository.full_name` to an entirely different, victim-owned repository tracked as a Stack. `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` for that victim stack with an attacker-chosen `after` SHA [4](#0-3) .
- `StatusHandler` is even less constrained: it matches purely by `Commit.where(sha: params.sha)` with no repository/organization scoping whatsoever [5](#0-4) . Any organization whose secret the attacker controls (or that has no secret configured) can be used to sign a forged `status` payload that injects a fabricated `success`/`failure` CI status for any commit SHA in the *entire* Shipit instance, regardless of which repository/organization that commit actually belongs to.

This is structurally the same class of bug as the referenced report: a verification step is bound to one identifier (organization via `webhook_secret`), while the state-changing operation is keyed off a different, uncorrelated identifier (repository `full_name` / bare commit SHA) that the verification never covered.

### Impact Explanation
On a multi-tenant Shipit deployment (the engine explicitly supports multiple GitHub Apps/organizations, each with its own `webhook_secret`, as shown in the secrets format docs and fixtures) [10](#0-9) , a party that legitimately controls (or was given) the webhook secret for their own onboarded organization can forge webhook events that:
- Trigger `sync_github` for a Stack belonging to a completely unrelated organization/repository they have no GitHub access to, feeding it an attacker-chosen `expected_head_sha` [4](#0-3) .
- Inject a fabricated successful CI/commit status for any commit SHA tracked anywhere in the instance via `StatusHandler`, with zero repository binding [5](#0-4) , which can satisfy blocking-status/CI gating used by Shipit's merge queue and deploy pipeline for a stack the attacker does not own.

This breaks the cross-repository write / unauthorized-merge boundary explicitly called out as in-scope Critical impact: an attacker with credentials for one tenant can write state (sync, fake CI status) into another tenant's repository/stack, potentially causing an unauthorized deploy or merge decision to be made on fabricated status data.

### Likelihood Explanation
Requires the attacker to hold a valid `webhook_secret` for at least one organization known to the Shipit instance (their own onboarded org in a multi-tenant setup, or any org whose secret was left unset, which `verify_webhook_signature` treats as auto-verified). This is a lower bar than compromising the victim organization's own secret, GitHub App private key, or session — it is exactly the "unprivileged attacker breaking a deployment-trust binding" pattern in scope (organization authenticated vs. repository actually written).

### Recommendation
- After signature verification, re-derive `repository.owner.login` (or `organization.login`) from the same payload and assert it matches the owner segment of `repository.full_name` before dispatching to handlers; reject mismatches with `422`.
- Scope `Handler#stacks` and `StatusHandler`'s commit lookup by the verified organization/repository, not solely by attacker-supplied `full_name` or bare `sha`.
- Do not treat an absent `webhook_secret` as an implicit "always verified" bypass; require a secret per configured organization or fail closed.

### Proof of Concept
1. Shipit instance is configured with two GitHub Apps: `attacker-org` (secret known to/controlled by the attacker's own onboarded organization) and `victim-org` (unrelated, tracked as `Stack` `victim-org/victim-repo`).
2. Attacker sends `POST /webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
   signed (`X-Hub-Signature`) with `attacker-org`'s `webhook_secret`.
3. `verify_signature` resolves `repository_owner` = `"attacker-org"`, verifies successfully against `attacker-org`'s secret [1](#0-0) .
4. `PushHandler#stacks` resolves the target via `repository.full_name` = `"victim-org/victim-repo"` [3](#0-2) , and `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` runs against the victim stack, despite the attacker never having proven control of `victim-org`.
5. Equivalently, a forged `status` event signed with any known-to-the-attacker org secret and an arbitrary tracked commit `sha` sets that commit's CI status via `StatusHandler`, with no repository check at all [5](#0-4) .

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
