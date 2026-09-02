### Title
Webhook signature verification is bound to `repository.owner.login`, not to the `repository.full_name` used to select the target Repository/Stack — cross-tenant/cross-repository event spoofing - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, taken from `payload.dig('repository', 'owner', 'login')` (or `organization.login`) [1](#0-0) [2](#0-1) . However, the handlers that actually locate the `Repository`/`Stack` to act on use a *different* field from the same payload, `repository.full_name` [3](#0-2) , which `Repository.from_github_repo_name` splits into owner/name independently of the signature check [4](#0-3) . Nothing ties `repository.owner.login` (used to pick the verifying secret) to the owner encoded in `repository.full_name` (used to select the record that gets mutated).

### Finding Description
`Shipit.github(organization: repository_owner)` looks up per-organization config (`webhook_secret`, `private_key`, etc.) keyed by `repository_owner` [5](#0-4) . The signature is HMAC-verified with that organization's secret against the raw JSON body [6](#0-5) .

The equality that should hold but doesn't is:
`organization authenticated by verify_signature (payload.repository.owner.login)` == `organization/repository actually written by the handler (payload.repository.full_name)`

Because these are two independently-controlled JSON fields inside the same signed body, an attacker who legitimately knows the `webhook_secret` for one tenant organization ("OrgA", e.g. because they administer OrgA's real GitHub App/webhook config and can therefore produce a validly-signed arbitrary payload) can set `repository.owner.login = "OrgA"` (so `verify_signature` passes using OrgA's secret) while setting `repository.full_name = "OrgB/target-repo"`. `Shipit::Webhooks::Handlers::Handler#stacks` then resolves the *target* repository purely from `full_name`, independent of the organization used for authentication [7](#0-6) .

This lets a validly-authenticated request for OrgA drive handler logic against OrgB's stacks/review stacks, e.g.:
- `PushHandler#process` triggers `stack.sync_github(expected_head_sha:)` for any stack matching the forged branch/ref on OrgB's repo [8](#0-7) .
- `PullRequest::ClosedHandler#process` calls `review_stack.archive!` on OrgB's review stack, resolved solely via `params.repository.full_name` [9](#0-8) .
- `PullRequest::LabeledHandler#process` can archive/unarchive OrgB stacks based on forged label data [10](#0-9) .

### Impact Explanation
This breaks the "organization authenticated vs. repository written" trust binding explicitly called out as in-scope. It allows cross-repository/cross-tenant actions (unarchiving/archiving stacks, forcing GitHub syncs, mutating pull-request state) on a repository the attacker was never authenticated for, using only credentials belonging to a different, unrelated tenant organization on the same Shipit instance. This matches the High/Critical "cross-repository writes" impact criterion.

### Likelihood Explanation
Exploitability requires the attacker to already possess a valid `webhook_secret` for *some* organization configured in the multi-org Shipit deployment (e.g., because they are a legitimate admin of that org's real GitHub App/webhook settings). This is a real-world condition in shared/multi-tenant Shipit installations where multiple, mutually-untrusting organizations are configured (`Shipit.github_organizations`) [11](#0-10) . Given that condition, forging the payload is trivial (just craft JSON with mismatched `owner.login` vs `full_name` and sign with the known secret), making likelihood moderate-to-high in multi-tenant setups, though it does not apply to single-organization deployments (`github_default_organization` nil case, where the check is not organization-specific) [12](#0-11) .

### Recommendation
In `WebhooksController#verify_signature`, after selecting the app/secret by `repository_owner`, also assert that `repository_owner` equals the owner segment parsed out of `payload.dig('repository', 'full_name')` (and equals `organization.login` when present) before proceeding; reject the request (`head(422)`) on mismatch. Equivalently, have `Shipit::Webhooks::Handlers::Handler#repository_name` reuse/validate against the same `repository_owner` value used for signature verification rather than trusting `full_name` independently.

### Proof of Concept
1. Configure Shipit with two orgs, `orga` and `orgb`, each with its own `webhook_secret` (multi-org mode).
2. As someone who knows `orga`'s `webhook_secret` (e.g., an admin of OrgA's GitHub App), craft a `pull_request` "closed" webhook payload:
```json
{
  "action": "closed",
  "number": 1,
  "pull_request": { "...": "..." },
  "repository": { "owner": { "login": "orga" }, "full_name": "orgb/target-repo" },
  "sender": { "login": "attacker" }
}
```
3. Sign the raw body with `orga`'s `webhook_secret` (HMAC-SHA1) and send it as `X-Hub-Signature` with `X-Github-Event: pull_request`.
4. `verify_signature` resolves `repository_owner == "orga"`, fetches `orga`'s app, and successfully verifies the signature [1](#0-0) .
5. `PullRequest::ClosedHandler` resolves `repository` via `params.repository.full_name == "orgb/target-repo"` [13](#0-12)  and calls `review_stack.archive!` on OrgB's review stack — an action never authenticated by OrgB.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L41-68)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

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
