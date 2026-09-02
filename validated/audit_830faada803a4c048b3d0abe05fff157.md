## Confirmed root cause

The signature check and the record lookup for a webhook use two different sub-fields of the same attacker-controlled JSON payload:

- `WebhooksController#verify_signature` picks the HMAC secret using `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), and validates the whole raw body against that org's `webhook_secret`. [1](#0-0) [2](#0-1) 
- Once the signature is accepted, every handler resolves the target `Stack`/`Repository` using a *different* field: `payload.dig('repository', 'full_name')` via `Handler#repository_name` / `Handler#stacks`. [3](#0-2) 
- `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on that branch of that repository — an operation that mutates commit history / deploy state. [4](#0-3) 
- `StatusHandler#process` writes a `Status` onto any `Commit` matching the given `sha`, independent of which repo it belongs to. [5](#0-4) 

Nothing ties `repository.owner.login` (the field the HMAC secret lookup is keyed on) to `repository.full_name` (the field used to select which `Stack`/`Repository` gets acted on) — the signature only proves the *raw bytes* were signed by whichever organization's secret got selected; it does not prove that `repository.owner.login` and `repository.full_name`'s owner are the same GitHub organization.

## Binding broken

`organization authenticated (repository.owner.login → webhook_secret lookup) == repository written (repository.full_name → Stack/Repository resolved by Handler#stacks)`

An attacker who legitimately controls an org connected to this Shipit instance (and therefore knows/derives that org's `webhook_secret` through its own GitHub App/webhook configuration) can craft a raw JSON body where `repository.owner.login` (and/or `organization.login`) is set to their own org — so `verify_signature` picks the correct secret and the HMAC passes — while `repository.full_name` is set to `"victim-org/victim-repo"`. Because handlers never re-validate that `full_name`'s owner matches the verified organization, the forged event is processed against the victim's stack. [6](#0-5) 

### Title
Webhook signature verification keys off `repository.owner.login` while handlers act on `repository.full_name`, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against based on `repository.owner.login`/`organization.login`, but `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name` (used by every handler, e.g. `PushHandler`, `StatusHandler`) resolve the affected `Repository`/`Stack`/`Commit` from a different field, `repository.full_name`. These two fields are never cross-checked, so a valid signature for organization A does not guarantee the payload's target repository actually belongs to organization A.

### Finding Description
`verify_signature` fetches `Shipit.github(organization: repository_owner)` and validates the HMAC of the raw POST body against that org's configured `webhook_secret`: [1](#0-0) 
`repository_owner` is derived purely from attacker-controlled JSON: [2](#0-1) 

After the signature is accepted, `WebhooksController#create` dispatches to registered handlers with the full, unmodified `params`: [6](#0-5) 

Every built-in handler resolves the target repository/stack using `repository.full_name`, a field the signature check never inspects or ties to `repository.owner.login`: [3](#0-2) 

`PushHandler` uses this to trigger `stack.sync_github` (a state-mutating operation reconciling commits/branch head) for the resolved stack: [4](#0-3) 

`StatusHandler` writes a `Status` onto any commit matching an attacker-chosen `sha`, regardless of which repository it came from: [5](#0-4) 

Because HMAC-SHA1 verification is only over the raw bytes and the *choice* of key (organization) is itself taken from an unauthenticated field that differs from the field actually acted upon, an attacker who is a legitimate tenant of organization A (and thus can obtain/derive org A's `webhook_secret`, e.g. by observing their own configured webhook deliveries) can sign a payload claiming `repository.owner.login: "org-a"` while setting `repository.full_name: "victim-org/victim-repo"`. The signature check passes (it's checking org A's secret against the raw body, and org A's secret is exactly what was used to sign it), but the handler acts on victim-org's stack/commits.

### Impact Explanation
This breaks the trust boundary between organizations onboarded to a single Shipit instance: any org's webhook secret can be used to forge push/status/check_suite events for a completely different, victim organization's repositories. Depending on which handler is targeted, this enables:
- Forged commit statuses on arbitrary commits (`StatusHandler`), which can flip a victim commit to `success`, satisfying `deployable?` checks that gate deploys — an unauthorized deploy path (`Commit#deployable?` at `app/models/shipit/commit.rb:227`). [7](#0-6) 
- Forced resynchronization of a victim stack's git state (`PushHandler` → `stack.sync_github`), altering which commits are considered deployed/undeployed.

This matches the "unauthorized deploy" / cross-organization-write class of impact called out as in-scope.

### Likelihood Explanation
Requires the attacker to be a legitimate, unprivileged tenant of at least one organization connected to the Shipit instance (no privileged Shipit account or GitHub App key needed) — they only need to know the `webhook_secret` value used for their own org's webhooks, which they control since they configure/receive its deliveries. This is plausible in any deployment supporting multiple organizations/tenants sharing the same Shipit instance, which the `Shipit.github(organization:)`-keyed configuration design implies is a supported use case.

### Recommendation
After signature verification succeeds, re-derive `repository_owner` and additionally verify that `repository.full_name`'s owner segment matches the organization whose secret validated the signature (i.e., reject if `payload.dig('repository','full_name')&.split('/')&.first&.downcase != repository_owner.downcase`). Alternatively, key handler lookups off the same verified organization identity rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Attacker legitimately connects "org-a" to the shared Shipit instance and knows/derives `org-a`'s `webhook_secret`.
2. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `sha1=HMAC(org_a_webhook_secret, raw_body)` and sets it as `X-Hub-Signature`, with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "org-a")` and successfully verifies the signature. [1](#0-0) 
5. `PushHandler#process` resolves stacks via `repository.full_name` = `"victim-org/victim-repo"` and calls `sync_github(expected_head_sha: "deadbeef...")` on the victim's stack, mutating its commit/deploy state despite the attacker never having credentials for `victim-org`. [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
