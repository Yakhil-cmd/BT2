### Title
Webhook signature is verified against the payload's claimed organization, but handlers write to repositories/commits with no matching authorization check, enabling cross-organization forgery of push/status events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `webhook_secret` to use for HMAC validation based on `repository_owner`, a value read directly from the attacker-supplied JSON body (`repository.owner.login` or `organization.login`). Once the signature check passes for that claimed organization, the JSON body is handed to `Shipit::Webhooks::Handlers` which act on a different field (`repository.full_name` for `PushHandler`, or nothing at all for `StatusHandler`) without re-verifying that the authenticated organization actually owns the repository/commit being mutated.

### Finding Description
`verify_signature` picks the `GitHubApp`/secret to check the HMAC against using: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization config (each org can have its own `webhook_secret`, as shown in the multi-org secrets fixture) and constructs a `GitHubApp` used purely to validate `X-Hub-Signature` against `request.raw_post`: [3](#0-2) [4](#0-3) 

Once the HMAC passes, the entire raw JSON payload is dispatched to handlers: [5](#0-4) 

Handlers derive the target repository from a *different* JSON field than the one used for signature routing. `Handler#repository_name` reads `repository.full_name`: [6](#0-5) 

Nothing in the code enforces that `repository.owner.login` (used to pick the secret) is consistent with `repository.full_name` (used to pick the target stacks). Because the whole request body is attacker-controlled JSON (only the HMAC over the raw bytes is checked, not the semantic content), an operator of a legitimate organization "attacker-org" configured in the same Shipit instance (each org gets its own `webhook_secret` per the multi-org config format) can craft a payload where `repository.owner.login` = `"attacker-org"` (so the signature check passes using that org's known secret) while `repository.full_name` = `"victim-org/victim-repo"`. `PushHandler` then resolves stacks purely from that spoofed `full_name` and triggers a sync of an attacker-chosen `after` SHA: [7](#0-6) 

Even more directly, `StatusHandler` performs **no repository binding check at all** — it looks up commits globally by `sha` and writes a forged CI status: [8](#0-7) 

This is the structural analog of the reported bug class: the report's root cause is that Chainlink's `latestAnswer()` return value is trusted without validating it corresponds to a fresh/authoritative round (`updatedAt`/`answeredInRound` binding broken). Here, the binding broken is: *the organization whose signature authenticated the webhook* vs. *the repository/commit that the handler actually writes to*. The engine authenticates "who signed this envelope" but acts on unauthenticated content inside the envelope claiming a different target.

### Impact Explanation
An attacker who legitimately controls one organization's GitHub App/webhook configuration in a multi-tenant Shipit deployment can forge `push` and `status` webhook events for any other organization's repositories/commits tracked by the same instance. Forged `status` events can mark arbitrary commits (in a completely different repository) as passing CI (`state: success`), and forged `push` events can force `stack.sync_github(expected_head_sha:)` for a victim's stack. Since Shipit's merge/deploy gating (`Status::Group`, `MergeRequest`, `DeploySpec`) is driven by exactly these status records, this can be leveraged toward an unauthorized deploy/rollback decision on a repository the attacker does not control — a cross-repository write with no repository-write GitHub credential of their own. This matches the "cross-repository writes / unauthorized deploy" Critical impact bucket.

### Likelihood Explanation
Requires a Shipit deployment configured for multiple GitHub organizations (documented, supported feature — `docs/setup.md`, `test/dummy/config/secrets_double_github_app.yml`) where the attacker legitimately administers one of those organizations' GitHub App (and therefore knows/controls its `webhook_secret`), but is unprivileged with respect to the victim organization's repository. No GitHub write access, Shipit session, or `ApiClient` token to the victim is needed — only the ability to POST an HMAC-valid request signed with the attacker's own org secret, with a crafted JSON body pointing at a different `repository.full_name`/`sha`.

### Recommendation
After signature verification, re-derive and cross-check that the organization implied by every field used downstream (`repository.full_name`'s owner segment, and any commit lookup) matches the organization whose secret validated the signature — reject the webhook if they diverge. For `StatusHandler`, scope the `Commit.where(sha: ...)` lookup by the repository/stack owned by the authenticated organization instead of a global SHA lookup.

### Proof of Concept
1. Shipit is configured with two orgs in `secrets.yml`: `attacker-org` (secret known to the attacker, who is a legitimate admin of that org's GitHub App) and `victim-org` (tracked stack `victim-org/victim-repo`).
2. Attacker computes `sha1=HMAC(attacker-org secret, body)` over a crafted JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success"
}
```
3. POST to `/webhooks` with `X-Github-Event: status` and the computed `X-Hub-Signature`.
4. `verify_signature` resolves `repository_owner` → `"attacker-org"`, verifies successfully with attacker-org's secret [1](#0-0) .
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — matching the victim's commit regardless of organization — and records a forged success status [8](#0-7) .

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
