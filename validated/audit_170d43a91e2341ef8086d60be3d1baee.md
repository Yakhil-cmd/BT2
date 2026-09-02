### Title
Cross-Organization Commit Status Forgery via Webhook Signature/Payload Binding Mismatch - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
Shipit's webhook authentication binds a signature check to the organization named in `repository.owner.login`, but the `status` event handler that then writes state acts only on the raw commit `sha` field from the same payload with no scoping to the repository/organization that was actually verified. This breaks the intended binding: `organization that authenticated == repository/commit that is written`.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate the signature against purely from a field inside the untrusted JSON body: [1](#0-0) [2](#0-1) 

Shipit explicitly supports configuring multiple, independent GitHub App installations for different organizations, each with its own `webhook_secret`: [3](#0-2) 

Because the HMAC signature is computed over the *entire* raw request body, an attacker only needs to legitimately possess (or have leaked to them) the `webhook_secret` for one configured organization ("Org A") to produce a validly-signed payload for *any* content whatsoever — including a `status` event body whose `sha` field references a commit that actually belongs to a completely different organization/repository ("Org B") also hosted on the same Shipit instance.

Once signature verification passes (bound to Org A), the event is dispatched to `StatusHandler#process`, which performs **no repository/organization scoping at all** — it looks up commits purely by `sha` across the entire database and writes the attacker-supplied state to them: [4](#0-3) 

The verified entity (Org A, via `repository_owner`) is never checked against the entity acted upon (the commit belonging to whatever stack/repository actually owns that `sha`). This is the same class of bug as the ZetaChain finding: a confirmation/authentication check is performed on one piece of context (the tracked/observed org) while the actual state mutation operates on unrelated, unverified data (any commit `sha` reachable in the payload).

### Impact Explanation
Commit statuses created via this path (`commit.create_status_from_github!`) are the same statuses Shipit's release/merge gating logic consults (`Status`, `ReleaseStatus`, merge queue checks). By forging a `status` webhook signed with credentials scoped to one organization, an attacker can inject a fabricated `success` (or `failure`) status onto a commit belonging to an entirely different, unrelated stack/organization configured on the same Shipit instance — bypassing CI/CD confirmation gates that other teams rely on to authorize merges and deploys. This crosses a trust boundary between organizations that the multi-org GitHub App feature is explicitly designed to keep separate, and can enable an unauthorized deploy/merge in a repository the attacker has no legitimate access to — matching the "unauthorized deploy, rollback or merge" / escalation impact category.

### Likelihood Explanation
Requires the attacker to hold a valid `webhook_secret` for at least one organization configured on the target Shipit instance (e.g., as an admin of their own org's GitHub App, or via a leaked secret for one tenant) — no repository write access or Shipit session/API token is needed. In any single-tenant (single `webhook_secret`) deployment this is not exploitable across repos since there is only one secret to begin with, but the moment a Shipit instance manages multiple GitHub organizations with per-org secrets (a documented, supported configuration), the isolation between them for the `status` event is entirely absent. This does not require guessing the correct commit `sha` for the target repo beyond what is normal public commit information.

### Recommendation
When processing any webhook event, resolve the target `Repository`/`Stack` from the verified organization/`repository.full_name` context established during signature verification, and scope all subsequent lookups (`Commit.where(sha:)`, stack lookups in `PushHandler`, `CheckSuiteHandler`, etc.) to that resolved repository — never trust `repository.owner.login` alone as a routing key while allowing a separately-named `full_name`/`sha` to be acted upon without cross-checking they belong to the same organization actually authenticated.

### Proof of Concept
1. Configure (or compromise) a Shipit instance with two organizations using the documented multi-org GitHub App layout, `OrgA` and `OrgB`, each with distinct `webhook_secret`s, per `lib/shipit.rb`'s `github_app_config`.
2. As someone who only knows `OrgA`'s `webhook_secret` (e.g. a legitimate admin of `OrgA`'s GitHub App settings), craft a `status` event JSON body:
   ```json
   {
     "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgA/irrelevant"},
     "sha": "<sha of a real commit belonging to a stack under OrgB>",
     "state": "success",
     "branches": [{"name": "main"}]
   }
   ```
3. Sign the raw body with `OrgA`'s `webhook_secret` (`sha1=HMAC(webhook_secret, body)`), and POST it to `/webhooks` with header `X-Github-Event: status`.
4. `WebhooksController#verify_signature` looks up `Shipit.github(organization: "OrgA")` and successfully verifies the signature, per `app/controllers/shipit/webhooks_controller.rb` lines 24-30.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)` with no organization/repo filter, per `app/models/shipit/webhooks/handlers/status_handler.rb` lines 20-24, and writes the forged `success` status onto the `OrgB` commit — even though the attacker was never authenticated for `OrgB`.

Note: I did not have remaining tool budget to fully inspect `app/models/shipit/webhooks/handlers/handler.rb`'s `stacks` helper (used by `PushHandler`/`CheckSuiteHandler`) to confirm whether it performs any repository-owner cross-check before scoping by `full_name`; based on the grep results it references `repository`/`full_name` fields from the same untrusted payload, so the same binding gap likely extends to those handlers, but this should be independently verified against the file contents.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
