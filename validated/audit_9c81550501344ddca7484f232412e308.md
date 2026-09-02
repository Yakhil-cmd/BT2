### Title
Webhook signature verification is scoped by `repository.owner.login`, but downstream handlers act on `repository.full_name` — an organization authenticated ≠ repository written binding break (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, which is read directly from the untrusted JSON payload (`repository.owner.login`, falling back to `organization.login`). However, every webhook handler (`Shipit::Webhooks::Handlers::Handler#stacks`, `PushHandler`, `StatusHandler`, etc.) resolves the actual `Repository`/`Stack`/`Commit` to mutate using a *different* field of that same untrusted payload: `repository.full_name`. Nothing binds these two fields together cryptographically. In a multi-organization Shipit deployment (explicitly documented and supported, see `config/secrets.development.example.yml` and `test/dummy/config/secrets_double_github_app.yml`), if any configured organization has no `webhook_secret` set, `GitHubApp#verify_webhook_signature` unconditionally returns `true` for that organization. An attacker can then send an unsigned/arbitrary-signed request claiming `repository.owner.login` = the org with no secret, while setting `repository.full_name` = `"victim-org/victim-repo"`, a completely different, properly-secured organization/repository. The signature check passes (because of the unrelated org's missing secret), but the handler acts on the victim repository's stacks.

### Finding Description
1. `WebhooksController#verify_signature` computes the trust-check target from the payload itself, not from any externally-verified source: [1](#0-0) [2](#0-1) 

2. `GitHubApp#verify_webhook_signature` has an explicit bypass for organizations without a configured secret: [3](#0-2) 

3. Multi-organization configuration, where each org has its own independent `webhook_secret` (which can legitimately be left blank per-org, as shown in the setup docs/example secrets), is a supported, documented configuration: [4](#0-3) 

4. After signature "verification" passes (based solely on `repository.owner.login`), the full raw, attacker-controlled JSON is dispatched to handlers, none of which re-check `repository.owner.login`. Instead they resolve the target strictly from `repository.full_name`: [5](#0-4) 

5. `PushHandler`, driven entirely by that unverified `full_name`-derived `stacks` scope, triggers a GitHub sync/deploy pathway (`stack.sync_github(expected_head_sha: params.after)`): [6](#0-5) 

6. `StatusHandler` is even more exposed: it does not use the per-repository `stacks` scoping at all, and updates status on *any* commit anywhere in the installation matching the attacker-supplied `sha`: [7](#0-6) 

**Binding equality that should hold, but doesn't:**
`organization used to select/verify the HMAC secret (repository.owner.login)` == `organization/repository actually mutated by the handler (repository.full_name)`.

Before the attacker's request: both fields are always consistent for real GitHub-originated webhooks (GitHub itself guarantees `full_name == "#{owner.login}/#{name}"`), so the binding holds implicitly by construction of genuine payloads.

After the attacker's request: since the entire JSON body is attacker-supplied and unauthenticated at the time `repository_owner` is computed, the attacker is free to set `repository.owner.login` to any configured-but-secretless org while independently setting `repository.full_name` to any other, protected org/repo. The equality breaks, and the "authenticated" identity (secretless org) no longer matches the "written" identity (victim repo/stack).

### Impact Explanation
This crosses the Critical bar of "an unauthorized deploy, rollback or merge": an attacker with no Shipit credentials, no GitHub App private key, and no access to the victim organization can forge push/status webhooks that are accepted as "signature verified" (because verification was keyed off an unrelated, secretless organization) and then act on a victim stack/repository belonging to a different, secured organization — potentially triggering `sync_github`/deploy pathways, or injecting arbitrary commit statuses across the whole install via `StatusHandler`, which could unblock/`deployable?` a malicious commit for later manual or continuous deployment.

### Likelihood Explanation
Requires: (a) the operator to run a multi-organization Shipit configuration (explicitly documented/supported feature) where at least one configured organization has no `webhook_secret` set, and (b) the attacker to know or guess that organization's name and the victim's `owner/repo` full name (both public information on GitHub). No authentication, token, or repository write access is needed to send the crafted HTTP request to the public webhooks endpoint. Given multi-org setups without a secret on every org are realistic (the example config even ships with `webhook_secret: # nil` templates), likelihood is moderate-to-high in such deployments.

### Recommendation
- Require `webhook_secret` to be present (fail closed) for every configured organization; do not allow `verify_webhook_signature` to return `true` when `webhook_secret` is blank.
- Re-derive/re-validate that `repository.full_name` (or `organization.login` for org-scoped events) is consistent with the `repository_owner`/org used to select the verifying secret before dispatching to handlers — i.e., assert `full_name.split('/').first == repository_owner` (case-insensitively) inside `verify_signature`, rejecting mismatches with 422.
- In `StatusHandler`, scope `Commit.where(sha: params.sha)` to commits belonging to the verified organization/repository rather than searching globally across all stacks.

### Proof of Concept
Given a Shipit deployment configured with two GitHub orgs, e.g.:
```yaml
github:
  OrgWithoutSecret:
    app_id: 1
    installation_id: 1
    webhook_secret: # nil
  VictimOrg:
    app_id: 2
    installation_id: 2
    webhook_secret: super-secret-value
```
An attacker (no credentials) sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything-or-omitted

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgWithoutSecret" },
    "full_name": "VictimOrg/victim-repo"
  }
}
```
`WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgWithoutSecret")`, whose `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb` lines 76-77) because that org has no `webhook_secret`. The request passes verification and is dispatched to `PushHandler`, which resolves stacks via `Repository.from_github_repo_name("VictimOrg/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb` lines 32-38) and calls `stack.sync_github(expected_head_sha: ...)` on the victim stack — despite the victim org's real `webhook_secret` never having been checked.

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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
