### Title
Webhook signature verified against `repository.owner.login`'s GitHub App while the affected repository is taken from the unauthenticated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to use for HMAC verification based on `repository.owner.login` (falling back to `organization.login`), but every downstream handler resolves the `Stack`/`Repository` it will act on from `repository.full_name` in the very same JSON body [1](#0-0) . Nothing binds `repository.owner.login` to `repository.full_name`'s owner segment before the signature is trusted, so in a multi-organization deployment (`Shipit.github(organization: ...)`, `github_app_config`) a party that legitimately controls one organization's webhook secret can forge a payload whose `owner.login` matches their own org (passing verification) but whose `repository.full_name` names a different organization's repository.

### Finding Description
`Shipit.github(organization:)` looks up a distinct `GitHubApp` (and thus a distinct `webhook_secret`) per GitHub organization via `github_app_config` [2](#0-1) . The webhook signature check is:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [3](#0-2) . This only proves the raw body was HMAC-signed with the secret configured for organization `repository_owner`; it says nothing about which repository the rest of the same JSON body claims to describe.

Every `Handler` subclass, however, resolves the target `Stack`/`Repository` independently from `repository.full_name`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) , and handlers such as `PullRequest::OpenedHandler` use `params.repository.full_name` to look up `Shipit::Repository.from_github_repo_name` and then create/unarchive/deploy review stacks under that repository [5](#0-4) [6](#0-5) .

The binding that is broken is: **the organization whose secret authenticated the request** (`repository.owner.login` used in `verify_signature`) **≠ the repository whose Stack is written to** (`repository.full_name` used everywhere else). In a normal, single GitHub App instance this is not exploitable because there is only one `webhook_secret`. It becomes exploitable specifically in the documented multi-organization mode (`Shipit.github_organizations`, `github_app_config`, `TOP_LEVEL_GH_KEYS`) where distinct organizations, each with their own webhook secret, are configured on the same Shipit instance — a supported, documented configuration in `lib/shipit.rb`.

### Impact Explanation
An attacker who legitimately holds the webhook secret for one tenant organization ("org-A") on a multi-tenant Shipit instance can craft an arbitrary payload with `repository.owner.login = "org-A"` (so it passes signature verification against org-A's secret) but `repository.full_name = "org-B/victim-repo"`. This lets them trigger handler logic (creating/unarchiving review stacks, closing PR-driven review stacks, membership/label changes, commit status updates, etc.) against a repository/organization they do not control, i.e. a cross-repository/cross-organization write performed without possessing the victim organization's own webhook secret. This matches the "cross-repository writes" high/critical impact class.

### Likelihood Explanation
Requires the specific, documented multi-organization configuration (more than one entry under `secrets.github` keyed by organization, each with its own `webhook_secret`), and requires the attacker to already legitimately control one tenant org's webhook secret (e.g., by being a member of a different customer organization on the same shared Shipit deployment). This is a real but narrower condition than a single-tenant install, so likelihood is moderate — plausible in any shared/multi-tenant Shipit deployment, not in the common single-org deployment.

### Recommendation
After signature verification succeeds, explicitly re-derive and cross-check the organization: parse `repository.full_name` and require its owner segment to equal `repository_owner` (the value used to select the verifying `GitHubApp`) before dispatching to any handler. Reject (422) the request if they differ. Alternatively, have `verify_webhook_signature` return the resolved organization and pass it down so handlers can assert `Repository.from_github_repo_name(full_name).organization == repository_owner` before performing any mutation.

### Proof of Concept
On a Shipit instance configured with two tenant organizations `org-a` and `org-b` (each with its own `webhook_secret` under `secrets.github[:org_a]` / `secrets.github[:org_b]`):
1. Attacker, a legitimate holder of `org-a`'s webhook secret, computes `sha1=HMAC(org_a_secret, body)` for a `pull_request` `opened` event JSON body where:
   - `repository.owner.login = "org-a"`
   - `repository.full_name = "org-b/victim-repo"`
2. POST this body with header `X-Hub-Signature: sha1=<computed>` to `/webhooks`.
3. `verify_signature` calls `Shipit.github(organization: "org-a").verify_webhook_signature(...)`, which succeeds because the signature was computed with `org-a`'s real secret [7](#0-6) .
4. `PullRequest::OpenedHandler#repository` then resolves `Shipit::Repository.from_github_repo_name("org-b/victim-repo")` [5](#0-4)  and, if provisioning is enabled, creates/unarchives a review stack for `org-b/victim-repo` on behalf of the attacker — despite the attacker never possessing `org-b`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L64-94)
```ruby
          def repo_name
            params.repository["full_name"]
          end

          def pr_number
            params.number
          end

          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```
