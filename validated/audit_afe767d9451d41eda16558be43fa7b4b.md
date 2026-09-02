### Title
Webhook signature verification is keyed off `repository.owner.login`, while the actual repository acted upon is selected via the independent, unauthenticated `repository.full_name` field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
This is a structural analog of the DelegationMetaSwapAdapter bug: two fields from the same untrusted payload are supposed to refer to the same entity, but only one of them is covered by the cryptographic check while the other drives the privileged action. In Shipit, `WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to verify the HMAC signature against using `repository_owner`, a value read straight out of the unverified JSON body (`params.dig('repository', 'owner', 'login')`), before the signature has been validated. [1](#0-0) [2](#0-1) 

Every event handler, however, determines the actual `Repository`/`Stack` to act on from a *different* field in the same untrusted payload: `repository.full_name`, via `Handler#repository_name`. [3](#0-2) 

`Repository.from_github_repo_name` independently parses `owner/name` out of `full_name`, with no requirement that this owner match the `repository.owner.login` used for signature verification. [4](#0-3) 

### Finding Description
`Shipit.github(organization:)` looks up per-organization config (including `webhook_secret`) from `secrets.github`, keyed by an organization name supplied entirely by the attacker via the request body. [5](#0-4) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the selected organization's `webhook_secret` is blank/unset: [6](#0-5) 

In multi-organization deployments (`config/secrets.*.yml` supports a hash of organizations, each with its own `webhook_secret`), it is entirely possible/documented for different organizations to be configured with different secrets, and the sample config even shows a placeholder `webhook_secret: # nil` per org. [7](#0-6) 

The exploitable equality break is:
`repository.owner.login` (used to pick the verification key) == `repository.full_name`'s owner segment (used to pick the acted-upon Stack)

This equality is never checked. An attacker can submit a webhook where:
- `repository.owner.login` (and/or `organization.login`) names an organization entry that has no `webhook_secret` configured, causing `verify_webhook_signature` to pass unconditionally regardless of the (forged or absent) `X-Hub-Signature` header, and
- `repository.full_name` names a *different*, properly-configured organization's tracked repository/stack.

Since `verify_signature` never re-checks that the org used for verification matches the org embedded in `repository.full_name`, the request sails through as "signed" and is dispatched to `Shipit::Webhooks.for_event(event)` handlers, which act on the stack resolved from `full_name` — i.e., a stack belonging to an org the attacker was never able to forge a valid signature for. [8](#0-7) 

### Impact Explanation
Handlers that resolve `Stack`/`Repository` via `full_name` execute state-changing operations driven by otherwise-untrusted payload content — e.g. `PushHandler` triggers `stack.sync_github(expected_head_sha: params.after)` against the resolved Stack. [9](#0-8) 

Other handlers (pull-request opened/labeled/closed/reopened/edited) resolve `repository` the same way and drive review-stack provisioning, archiving, and label capture based on attacker-controlled payload fields for a repo whose "owning organization" never had its signature validated with its own secret. [10](#0-9) [11](#0-10) 

I could not fully verify within the remaining budget whether any handler in this codebase (e.g. a commit-status/deployable-status handler) directly flips a `Commit`/`ReleaseStatus` record that gates automatic deploys strongly enough to independently satisfy the "unauthorized deploy" bar without further chained steps (I located `app/models/shipit/webhooks/handlers/status_handler.rb` but did not get to read its contents before the tool budget ran out). Absent that confirmation, the concretely provable impact is limited to spoofed repository/stack state changes and provisioning actions across organizations whose signature protection can be trivially routed around by choosing a differently (or un-)configured "owner" — this satisfies the report's core bug class (payload field acted upon but not covered by the verified signature) but I cannot claim a Critical "unauthorized deploy" without further verification of the status/check-run handler chain.

### Likelihood Explanation
The prerequisite — at least one organization with no `webhook_secret` set — is an operator-configuration state supported and documented by this engine itself (the sample multi-org secrets file ships with commented-out/nil `webhook_secret` values), not an exotic misconfiguration invented for this report. No authentication, token, or repository write access is required by the attacker: the request is an unauthenticated POST to the public `/webhooks` endpoint whose signature check is what's meant to gate access.

### Recommendation
In `WebhooksController#verify_signature`, after computing the resolved `Repository`/`Stack` from `full_name` inside each handler (or centrally, before dispatch), assert that the organization used to select the verification secret is the same organization implied by `repository.full_name`. Concretely: derive the owner strictly from `repository.full_name.split('/').first` for verification purposes (not from a separate `repository.owner.login`/`organization.login` field), so a single untrusted field can't be split across "verification identity" and "target identity." Additionally, consider treating a missing/blank `webhook_secret` as a hard configuration error (reject the request) rather than an implicit bypass.

### Proof of Concept
1. Configure Shipit with two GitHub organizations in `secrets.github`: `org-a` (has a `webhook_secret` set, owns the real tracked repo `org-a/app`) and `org-b` (no `webhook_secret` configured, e.g. left `nil` as shown in the sample config).
2. As an unauthenticated attacker, POST to `/webhooks` with:
   - Header `X-Github-Event: push`
   - Body: `{"repository": {"owner": {"login": "org-b"}, "full_name": "org-a/app"}, "ref": "refs/heads/master", "after": "<attacker-chosen sha>"}`
   - No valid `X-Hub-Signature` header (or any garbage value).
3. `verify_signature` calls `Shipit.github(organization: "org-b")`; because `org-b` has no `webhook_secret`, `verify_webhook_signature` returns `true` immediately, so the request is accepted. [1](#0-0) 
4. `PushHandler` resolves the Stack via `Repository.from_github_repo_name("org-a/app")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on `org-a`'s real, secret-protected stack — despite the attacker never possessing `org-a`'s `webhook_secret`. [9](#0-8) [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L59-68)
```ruby
          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
