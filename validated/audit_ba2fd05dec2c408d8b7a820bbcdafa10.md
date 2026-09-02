### Title
Webhook signature verification is bound to an unverified `repository.owner.login`/`organization.login` field, letting a payload's `repository.full_name`/`sha` act on stacks belonging to a different, unverified organization - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC against using `repository_owner`, a field taken directly from the *unverified* JSON body, and then the handlers that actually mutate state (`PushHandler`, `StatusHandler`, `LabeledHandler`, etc.) act on a *different* field of that same unverified body (`repository.full_name`, or in the `status` event's case, a bare `sha` with no repository scoping at all). The signature only proves the payload came from whichever organization's app was selected by `repository_owner` - it proves nothing about the `repository.full_name`/`sha` the handler actually operates on. This is the same class of bug as M-14: an authorization key (`vaults[address(vault)]`, here the org selected via `repository_owner`) is checked, but the object actually acted upon (lending to any vault type / here, any stack matching `repository.full_name` or `sha`) is not constrained to correspond to the verified key.

### Finding Description
`verify_signature` computes `repository_owner` from the raw, not-yet-verified payload and uses it to fetch the matching `GitHubApp` config, then verifies the signature with *that* app's `webhook_secret`: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` explicitly treats an organization with no configured `webhook_secret` as always-valid: [3](#0-2) 

`docs/setup.md`/`test/dummy/config/secrets_double_github_app.yml` show `webhook_secret` is an optional, per-organization setting (can legitimately be left nil for one org in a multi-organization Shipit deployment): [4](#0-3) 

Once `verify_signature` passes, `WebhooksController#create` dispatches the *entire raw payload* to handlers, and the handlers resolve the actual repository/stack/commit to mutate using a completely separate field of the same payload: [5](#0-4) [6](#0-5) 

`StatusHandler` is the most severe instance: it doesn't even scope by repository, only by `sha`, so it applies a forged commit status to **every** `Commit` record across **every** stack (potentially owned by a different, fully-secured organization) sharing that SHA: [7](#0-6) 

Equality that should hold but is broken: `organization whose webhook_secret authenticated the request == organization owning the repository/stack the handler writes to`. Before the attack, these are implicitly assumed equal because a legitimate GitHub webhook always sets `repository.owner.login` and `repository.full_name` consistently. After the attack, an unprivileged party who knows (or exploits) one organization's weak/absent `webhook_secret` sends a payload where `repository.owner.login`/`organization.login` names that weak org (to pass `verify_signature`) while `repository.full_name` (or `sha`, for `status` events) names a resource under a different, properly-secured organization.

### Impact Explanation
This crosses the trust boundary between organizations configured in `Shipit.github` (`Shipit.github_teams`/per-org `webhook_secret` isolation is the entire point of multi-tenant configuration) without any GitHub-side credential for the target organization. Concretely:
- `StatusHandler` lets the attacker forge CI/check `commit_status` (success/failure) on any tracked commit it can guess the `sha` of (trivially obtainable from any public repo or from Shipit's own UI), which can flip a commit's `deployable?`/required-check state used by continuous deployment - this is a path toward an **unauthorized deploy** by satisfying the checks Shipit's continuous-deployment logic gates on.
- `PushHandler`/`LabeledHandler`/`ReviewStackAdapter` allow forging pushes, PR label transitions, and archive/unarchive of `ReviewStack`s belonging to a repository the attacker does not control, purely by picking a differently-named `repository.full_name` while authenticating as a weakly-configured sibling organization.

This matches the required "High" bar (escalation past intended authorization boundaries, ability to influence an unauthorized deploy) and potentially "Critical" if it results in an actual unauthorized ship via forged deployable-status.

### Likelihood Explanation
Requires: (a) a Shipit instance configured with more than one GitHub organization/app, and (b) at least one of those organizations configured without a `webhook_secret` (a documented, supported configuration per `docs/setup.md`/the dummy secrets fixture) or one whose secret the attacker has otherwise obtained. Multi-org Shipit deployments are an explicitly supported and tested configuration (`secrets_double_github_app.yml`), so this is a realistic operational scenario, not a purely theoretical one. No repository write access, `ApiClient` token, or session is needed - only the ability to POST an HTTP request to `/webhooks`.

### Recommendation
Bind the field used to select the verifying `webhook_secret` to the field(s) later used by handlers to identify the target repository/stack: e.g., re-derive `repository_owner` from the same `repository.full_name` used by `Handler#repository_name`, or explicitly require and check that `repository.owner.login == repository.full_name.split('/').first`. Additionally, `StatusHandler` should validate the owning repository of matched commits/stacks against the organization that was actually authenticated via `verify_webhook_signature`, not act on bare `sha` matches globally. Consider also disallowing organizations without a configured `webhook_secret` from downgrading `verify_webhook_signature` to `true` in any multi-organization Shipit deployment.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (secured, `webhook_secret` set, owns tracked repo `OrgA/secret-repo`) and `OrgB` (no `webhook_secret` configured, as legitimately supported per `secrets_double_github_app.yml`).
2. Attacker (no credentials, no repo access) crafts a `status` webhook POST to `/webhooks` with `X-Github-Event: status`, no valid signature header (or any garbage), and body:
```json
{
  "sha": "<sha-of-a-commit-tracked-under-OrgA/secret-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgB/whatever" }
}
```
3. `verify_signature` computes `repository_owner == "OrgB"`, loads `OrgB`'s `GitHubApp`, and since `OrgB.webhook_secret` is blank, `verify_webhook_signature` returns `true` unconditionally regardless of the (missing/invalid) signature header. [3](#0-2) 
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which is not scoped to `OrgB` at all, and applies the forged `success` status to the real `OrgA/secret-repo` commit. [7](#0-6) 
5. If `OrgA`'s stack has continuous deployment gated on that check context, this forged status can unblock an automatic, unauthorized deploy of `OrgA/secret-repo` - achieved entirely without any `OrgA` credential.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
