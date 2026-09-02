Confirmed root cause: this is a multi-tenant deployment (`Shipit.github(organization:)` keyed off `github_default_organization`/`github_organizations`, each org with its own `webhook_secret` via `github_app_config`). The webhook signature is verified using the organization derived from `repository_owner` (`params.dig('repository','owner','login')` or the `organization.login` fallback), while every write path (`Handler#stacks`/`#repository_name`, all PR handlers, `Repository.from_github_repo_name`) resolves the target repository from the independent `repository.full_name` field, which is never checked against `repository.owner.login`.

### Title
Webhook signature is verified against `repository.owner.login`'s organization while writes are keyed on the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) is used to validate `X-Hub-Signature` based on `repository_owner`, computed from `params.dig('repository','owner','login')`. However, every handler that actually performs a write (`Shipit::Webhooks::Handlers::Handler#repository_name`, `PushHandler`, `PullRequest::*Handler`, `MembershipHandler`) resolves the target `Repository`/`Stack` via the separate, attacker-controlled `repository.full_name` field, using `Repository.from_github_repo_name`. The signature check never verifies that `full_name` and `owner.login` refer to the same repository/organization.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` (lines 24-49) does: [1](#0-0) 

`repository_owner` is derived purely from `repository.owner.login` (with `organization.login` fallback): [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization webhook secret via `github_app_config(organization)`, keyed on `secrets.github` map — in a multi-tenant install each org has its own independent `webhook_secret`: [3](#0-2) 

But the actual write target for every handler is computed from a *different* payload field, `repository.full_name`, never cross-checked against `repository.owner.login`: [4](#0-3) [5](#0-4) 

`PushHandler` uses `stacks` (built from `repository_name` = `full_name`) to trigger `stack.sync_github`: [6](#0-5) 

All `PullRequest` handlers (`opened`, `closed`, `labeled`, `unlabeled`, `reopened`, `edited`) similarly resolve `repository` from `params.repository.full_name`, independent of the org used for signature verification: [7](#0-6) 

**Binding that should hold, but is broken:** `organization authenticated (repository.owner.login, used to pick webhook_secret)` == `repository actually written (repository.full_name, used to resolve Stack/Repository)`. Before the attack: for legitimate GitHub deliveries these two fields always agree because GitHub itself populates both from the same repository object. After the attack (an attacker who can deliver an unsigned/mis-signed webhook payload, e.g., because their own organization has no `webhook_secret` configured — `verify_webhook_signature` returns `true` when `webhook_secret` is blank per `lib/shipit/github_app.rb` — or because they know their own org's secret and can sign with it), the attacker sets `repository.owner.login` to their own (unprotected/known-secret) organization while setting `repository.full_name` to `victim-org/victim-repo`. The signature check passes against the attacker's own org config, but the handler acts on the victim's repository/stack.

### Impact Explanation
This lets an attacker holding no legitimate credentials to the victim's GitHub org forge webhook events that get processed as if genuinely sent for the victim's repository: trigger `stack.sync_github` (Github sync job) for arbitrary stacks, manipulate `PullRequest`/`ReviewStack` archive/unarchive/provisioning-queue state for a victim's review-stack repository, or fabricate commit `status` updates that unblock deploy gating (`ci.require`/`blocking` checks) for the victim's stack. Because this can influence "deployable" status and archive/unarchive/provisioning flows for a stack the attacker does not own, this can be leveraged toward an unauthorized deploy/rollback path, satisfying the High-impact category ("escalation ... or an unauthorized deploy").

### Likelihood Explanation
This requires that the deployment be configured with the multi-organization GitHub config (per-org `webhook_secret` via `github_app_config`), and that the attacker control (or have unprotected/no-secret) at least one organization entry recognized by the Shipit instance, or otherwise be able to produce a validly-signed payload for some organization while spoofing the `repository.full_name` field of another. Given many real deployments run a single shared GitHub App config (`github_default_organization` nil path uses `secrets.github` directly for all organizations, bypassing the per-org lookup entirely), the multi-tenant configuration required for this specific mismatch to matter is a narrower deployment shape, moderating overall likelihood, but the code path exists and is reachable exactly as coded for any multi-org secrets.yml.

### Recommendation
When resolving the target `Repository`/`Stack` in `Shipit::Webhooks::Handlers::Handler` (and all subclasses), validate that `payload.dig('repository','owner','login')` matches the owner segment of `payload.dig('repository','full_name')` before acting, or better, verify the webhook signature using the organization implied by `repository.full_name` rather than the separate `owner.login`/`organization.login` fields, so that the field covered by the signature check is exactly the field used to select the write target.

### Proof of Concept
1. Configure Shipit with multi-org GitHub settings (`secrets.github` with named organizations, e.g. `attacker-org` and `victim-org`), each with its own `webhook_secret`.
2. As the attacker, send a POST to `/github/webhooks` with header `X-Github-Event: push`, `X-Hub-Signature` correctly computed using `attacker-org`'s `webhook_secret`.
3. In the JSON body, set `repository.owner.login = "attacker-org"` (so `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and the signature check passes) but set `repository.full_name = "victim-org/victim-repo"` and `ref`/`after` to a chosen SHA.
4. `WebhooksController#create` dispatches to `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` for the victim's stack — despite the signature only having been validated against the attacker's own organization secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
