### Title
Cross-organization webhook secret confusion allows commit-status forgery across repositories - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret used to authenticate an incoming GitHub webhook based on an attacker-controlled field inside the very payload being verified (`repository.owner.login`, falling back to `organization.login`), while the handler that actually acts on the payload (`StatusHandler`) uses a completely different, unscoped field (`sha`) to decide what data gets mutated. The "authenticated organization" and the "repository/commit that is written" are never bound together, breaking the equality `organization-that-signed == repository/commit-that-is-modified`.

### Finding Description
`Shipit::WebhooksController#verify_signature` picks which `GitHubApp`/secret to use for HMAC verification purely from payload fields the attacker fully controls before verification happens: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves this org name against `secrets.github` when the multi-org configuration schema is used (documented in `config/secrets.development.example.yml`), each organization having its own independent `webhook_secret`: [3](#0-2) 

Because the HMAC covers `request.raw_post` (the whole JSON body, including `repository.owner.login`), an attacker who legitimately controls one organization on a shared/multi-tenant Shipit instance (and therefore legitimately knows that organization's `webhook_secret`, e.g. through an installed GitHub App they administer) can craft an entire payload themselves: they set `repository.owner.login`/`organization.login` to *their own* org (so `verify_signature` fetches their own known secret and the HMAC validates), while filling in unrelated fields such as `sha` with data belonging to a *victim's* stack/commit.

`Shipit::Webhooks::Handlers::StatusHandler#process` never re-checks the repository the status belongs to — it looks up commits **globally** by `sha` alone: [4](#0-3) 

`Commit#create_status_from_github!` then records the forged status and, depending on state transitions, emits `deployable_status` and triggers `stack.schedule_merges`: [5](#0-4) 

So the signature verification binds "this request came from organization X" but the object actually mutated (`Commit` by raw `sha`, with no repository/org check at all) is completely decoupled from X. The base `Handler` class does have a repository-scoping helper (`stacks`, keyed on `payload.dig('repository', 'full_name')`), but `StatusHandler` doesn't use it at all, and even for handlers that do use `repository.full_name` (e.g. `PushHandler`, PR handlers), that field is likewise not covered by the org-selection logic and can independently be set to point at a different repository than the one whose secret was used to sign.

### Impact Explanation
An attacker who administers one org configured on a shared Shipit deployment (multi-org schema) can forge a "status" webhook, signed with their own org's `webhook_secret`, that marks an arbitrary commit belonging to a **different** organization's tracked stack as `success`. Since `add_status`/`schedule_merges` treats a successful status transition as a trigger for automatic merges and gates deploy-readiness, this can cause Shipit to consider a victim's untested/unreviewed commit as CI-green, enabling an **unauthorized merge or deploy** for a repository the attacker has no legitimate access to — a cross-repository, cross-organization write that breaks Shipit's trust boundary between webhook-signing organizations.

### Likelihood Explanation
Requires the target Shipit instance to use the multi-organization `github:` secrets schema (explicitly documented and supported) and requires the attacker to control (own the webhook secret of) at least one of the configured organizations — a realistic scenario for shared/self-hosted Shipit instances serving multiple orgs/teams. No access to the victim organization's secret, GITHUB_TOKEN, or Shipit session is required.

### Recommendation
Bind the verified organization to the actual repository being mutated: after signature verification, re-derive the repository from the same trusted party used to select the secret (or vice-versa), and reject/short-circuit processing when `repository.full_name`'s owner does not match the organization whose secret validated the signature. `StatusHandler` (and any handler relying on unscoped lookups like `Commit.where(sha:)`) should be updated to scope updates through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and verify that repository's owning organization matches the one used in `verify_signature`.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with a distinct `webhook_secret` (multi-org schema).
2. Attacker knows `attacker-org`'s webhook secret (legitimately, as its GitHub App owner).
3. Attacker crafts a JSON body:
```json
{
  "sha": "<victim commit sha tracked by a victim-org stack>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/irrelevant-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker_org_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `Shipit.github(organization: 'attacker-org')` from `repository.owner.login`, validates the signature successfully against `attacker-org`'s secret.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which matches the victim's commit regardless of `repository.full_name`, and creates a forged `success` status for it, potentially triggering `deployable_status`/`schedule_merges` on the victim's stack.

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

**File:** app/models/shipit/commit.rb (L366-384)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
