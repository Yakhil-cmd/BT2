### Title
Webhook signature verification keys on `repository.owner.login`/`organization.login` while all handlers act on `repository.full_name`, allowing cross-organization forged webhooks in multi-org deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In a multi-GitHub-App Shipit deployment (one `webhook_secret` per organization), `WebhooksController#verify_signature` selects which organization's secret to verify the HMAC signature against using a field taken from the attacker-controlled JSON body itself, not from any field bound to the actual target repository used later by the event handlers.

### Finding Description
`WebhooksController#verify_signature` computes the signing organization from the payload: [1](#0-0) 

and verifies the raw body against that organization's secret: [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config only when multiple GitHub Apps are configured (`Shipit.github_default_organization`) via `Shipit.github_app_config`: [3](#0-2) 

Once signature verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs, and every handler resolves the target `Repository`/stacks from a *different* field of the same body — `repository.full_name` — via `Handler#repository_name`/`#stacks`: [4](#0-3) 

`Repository.from_github_repo_name` splits that string on `/` with no cross-check against `repository.owner.login`: [5](#0-4) 

Because the HMAC covers the raw request body and the attacker is the legitimate holder of one organization's `webhook_secret` (they configured/received it when their org's GitHub App was registered on the shared Shipit instance), the attacker can craft an arbitrary JSON body — sign it correctly with their own org's secret — while setting `repository.full_name` to `victim-org/victim-repo` and `repository.owner.login`/`organization.login` to their own org. `verify_signature` will authenticate the request using the attacker's own valid secret, but `PushHandler`/`StatusHandler`/etc. will act on the victim's repository resolved purely from `full_name`: [6](#0-5) [7](#0-6) 

This breaks the required binding: `organization authenticated by verify_signature (repository_owner) == repository written by the handler (repository.full_name)`. Documentation confirms multi-org configuration is a supported, in-scope deployment mode with per-org `webhook_secret` values.

### Impact Explanation
An attacker who legitimately controls one GitHub organization/App registered on a shared multi-org Shipit instance can forge webhooks that are authenticated using their own secret but are processed against another organization's repository/stack. Concretely this allows:
- `push` events to trigger `stack.sync_github(expected_head_sha:)` on a victim stack the attacker doesn't own (`PushHandler#process`), influencing which commit Shipit considers deployable.
- `status` events to fabricate CI status for a victim commit (`StatusHandler#process` → `Commit#create_status_from_github!`), which can satisfy `ci.require` gating and enable an unauthorized deploy of that commit through the merge queue / deploy flow.

This is a cross-organization write into another repository's Shipit-tracked state, crossing the "unauthorized deploy" impact bar without the attacker ever needing credentials to the victim org.

### Likelihood Explanation
Requires: (a) the target instance uses the multi-organization GitHub App configuration schema (explicitly documented and supported), (b) the attacker's own organization/App is one of the configured organizations (so they know that org's `webhook_secret`), and (c) a repository with `owner/name` matching the forged `full_name` already exists as a `Shipit::Repository` with active stacks. All are realistic for any multi-tenant Shipit deployment shared across several organizations, which is exactly the scenario the multi-org config exists to support.

### Recommendation
Bind signature verification to the same identity used for repository resolution: after computing `repository_owner` for `Shipit.github`, also derive the effective owner from `repository.full_name` (or `organization.login` for org-scoped events) and reject the webhook (422) unless the two agree. Alternatively, verify the signature and then re-derive/enforce that any repository or stack acted upon belongs to the authenticating organization before invoking handlers.

### Proof of Concept
1. Deploy Shipit with multi-org config: `secrets.github` containing both `attacker-org` and `victim-org` app configs, each with distinct `webhook_secret`s (per `docs/setup.md` "Using Multiple Github Applications").
2. Victim already has a `Shipit::Repository` `victim-org/victim-repo` with stacks tracked in this instance.
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker_webhook_secret, raw_body)>` and POSTs to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner` = `"attacker-org"` (from `repository.owner.login`), fetches `Shipit.github(organization: 'attacker-org')`, and `verify_webhook_signature` succeeds because the attacker signed with their own valid secret.
6. `PushHandler#process` runs `Handler#stacks` → `Repository.from_github_repo_name('victim-org/victim-repo')` → resolves the victim's real stacks and calls `stack.sync_github(expected_head_sha: params.after)` using attacker-supplied data, despite the request never being authenticated by anything belonging to `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
