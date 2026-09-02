## Title
Webhook signature verification is keyed by an unauthenticated payload field, allowing cross-organization event forgery in multi-org deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using a value read out of the *same, attacker-supplied* request body (`repository.owner.login` or `organization.login`), rather than a fixed, trusted identity tied to the endpoint or delivery. The rest of the pipeline (`Handler#repository_name`, `Repository.from_github_repo_name`) then acts on a *different* field of that same unauthenticated body — `repository.full_name` — to decide which `Stack`/`Repository` record to mutate. This breaks the binding "organization whose secret authenticated the request == repository that is written," in installations that configure more than one GitHub organization (`Shipit.github_organizations`).

### Finding Description
In `verify_signature`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` looks up per-organization app config (`app_id`, `webhook_secret`, etc.) via `github_app_config`, keyed strictly by the `organization` argument passed in: [2](#0-1) 

Once the signature check passes, `Handler#stacks`/`#repository_name` resolve the target repository from a *different* JSON field, `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

Because both `repository.owner.login` (used for auth) and `repository.full_name` (used for the actual DB lookup/action) are attacker-controlled JSON fields inside the same unsigned-until-verified body, an attacker who is able to produce a validly-signed payload for *one* organization configured on the instance (e.g., because they administer their own org that is also configured on a shared/multi-tenant Shipit instance, per `docs/setup.md`'s "Using Multiple Github Applications" feature) can set `repository.owner.login` to their own org (so `Shipit.github(organization: "attacker-org")` resolves to a secret they can compute the HMAC with) while setting `repository.full_name` to `"victim-org/victim-repo"`. The signature check only validates that *some* HMAC over the raw body matches *a* configured secret for the org named in the body — it never confirms that the org used for authentication actually owns the repository the payload claims to act upon.

Push events reaching `PushHandler#process` would then call `stack.sync_github(expected_head_sha: ...)` on stacks belonging to `victim-org/victim-repo`, and `pull_request` handlers (`OpenedHandler`, `ClosedHandler`, etc.) resolve `Repository.from_github_repo_name(params.repository.full_name)` the same way, driving stack creation/archival for a repository the attacker does not control. [4](#0-3) [5](#0-4) 

This is the same class of bug as the report: the trust decision (signature verification) is scoped to a value (`repository_owner`) that is disjoint from the value actually acted upon (`repository.full_name`), so an entity that legitimately controls credentials for org A can still act on org B's resources — analogous to "the solver being punished/credited for something outside the scope that was actually verified."

### Impact Explanation
This allows cross-repository/cross-organization writes: an attacker who administers one org configured on a shared multi-org Shipit deployment can forge push/pull_request/status webhook events that are accepted as authentic for a *different* organization's repositories, triggering unauthorized syncs, review-stack creation/archival, or commit status changes on stacks they do not own — matching the Critical "cross-repository writes" impact category.

### Likelihood Explanation
This requires the deployment to use the multi-organization `github:` secrets schema (`Shipit.github_organizations` returning more than `[nil]`) and requires the attacker to control a valid `webhook_secret` for at least one configured organization (e.g., their own org, which they legitimately administer and can install the shared GitHub App on). No compromise of the victim org's secret is needed. Single-org deployments (the common case) are not affected because `repository_owner` is ignored when `github_default_organization` is `nil`.

### Recommendation
Do not select the verification secret from an unauthenticated field of the payload being verified. Either:
- Verify the signature against every configured organization's secret and require that the winning organization's login matches the `owner` of the `repository.full_name` used later in processing, or
- After signature verification succeeds against `repository_owner`'s secret, assert `repository.full_name.split('/').first == repository_owner` (case-insensitively) before dispatching to handlers, rejecting mismatches with `422`.

### Proof of Concept
1. Deploy Shipit with a multi-org `github:` config containing `attacker-org` and `victim-org`, each with distinct `webhook_secret`s (a legitimate multi-tenant setup per `docs/setup.md`).
2. As the admin of `attacker-org`, compute `sha1=HMAC(attacker_org_webhook_secret, body)` for a push payload body where:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/victim-repo"`
3. POST this body with `X-Hub-Signature` set to the computed HMAC and `X-Github-Event: push` to `/github/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully against `attacker-org`'s own secret.
5. `PushHandler` then resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github` on its stacks — an action the attacker should not be authorized to trigger.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
