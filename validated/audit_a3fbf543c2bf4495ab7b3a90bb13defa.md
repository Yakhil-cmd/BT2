### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but handlers act on the independent, unchecked `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-GitHub-App deployments, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the still-unverified JSON body. Once the signature is accepted, every event `Handler` independently re-reads the same raw payload and resolves the target `Stack` using the completely separate `repository.full_name` field, with no check that the two identify the same organization/repository.

### Finding Description
`verify_signature` computes the app/secret to verify against like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the untrusted JSON body before any cryptographic check has passed, and it is used only to pick `Shipit.github(organization: repository_owner)` — i.e., which of potentially many configured `webhook_secret`s (one per GitHub organization, as documented for the "Using Multiple GitHub Applications" setup) is used to validate `X-Hub-Signature`: [3](#0-2) [4](#0-3) 

After verification succeeds, the exact same raw body is dispatched to handlers: [5](#0-4) 

Every handler resolves its target `Stack`/`Repository` using a *different* field, `repository.full_name`, with no cross-check against `repository.owner.login`: [6](#0-5) [7](#0-6) [8](#0-7) 

The trust binding that should hold is: `organization_used_for_signature_verification == organization_of_repository_acted_upon`. Nothing enforces this equality — exactly the analog of the reported bug class ("a slippage/parameter value used to authorize an action is never validated against the value the action actually applies to"). The multi-org config is a documented, supported feature, not a deviation from how the engine is meant to be mounted.

### Impact Explanation
An attacker who legitimately controls a GitHub organization/App configured on the same Shipit instance (this is a normal, low-trust scenario supported by the "Using Multiple GitHub Applications" setup, and does not require any Shipit account, `ApiClient` token, or the *target* org's secrets) knows their own org's `webhook_secret`. They can craft and POST a payload where:
- `repository.owner.login` = their own org (so `verify_signature` picks their own valid secret and the HMAC check passes), but
- `repository.full_name` = `"victim-org/victim-repo"` (an entirely unrelated repository/organization they have no access to).

Because `Handler#stacks` and `Handler#repository_name` only look at `full_name`, the forged webhook is processed against the victim's `Stack`. Depending on event type this enables:
- `push`: force `stack.sync_github(expected_head_sha: ...)` with an attacker-chosen SHA on the victim stack.
- `status`: forge `commit.create_status_from_github!` on a victim commit, potentially satisfying required-status checks used by the merge queue/deployability logic, enabling an unauthorized merge or deploy.

This crosses the "cross-repository writes" / "unauthorized deploy, rollback or merge" impact bar from the rules.

### Likelihood Explanation
Requires: (a) the host to run Shipit with multiple GitHub Apps/organizations configured (a documented, supported deployment mode) and (b) the attacker controls at least one of those organizations' webhook secrets — a low bar since organization admins routinely have this. No Shipit account, `ApiClient` token, or victim-org secret is needed, satisfying the "unprivileged attacker" requirement in the rules.

### Recommendation
Bind the signature-selection organization to the organization actually acted upon: after verifying the signature, re-derive the target repository/stack strictly from `repository.owner.login` (the same field used to select the secret) rather than trusting `repository.full_name` independently, or explicitly assert `repository.full_name.split('/').first.casecmp(repository_owner) == 0` before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two GitHub Apps/orgs, `OrgA` (attacker-controlled, webhook secret known to attacker) and `OrgB` (victim), per `docs/setup.md`'s multi-org section.
2. Attacker computes `sha1=HMAC(OrgA_webhook_secret, body)` for a payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. POST to `/github/webhooks` with `X-Github-Event: push` and the computed `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: 'OrgA')` and succeeds (attacker's own valid secret), then `PushHandler` resolves `Repository.from_github_repo_name('OrgB/victim-repo')` and calls `sync_github` on the victim stack — a cross-organization action the attacker was never authorized to trigger.

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
