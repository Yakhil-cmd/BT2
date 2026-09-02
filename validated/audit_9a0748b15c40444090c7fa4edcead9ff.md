### Title
Webhook signature is verified against the organization derived from `repository.owner.login`/`organization.login`, but every handler resolves the target Stack from the independently-controlled `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to check the HMAC signature against using a value taken from the same untrusted JSON body it is trying to authenticate, while every `Handler` subclass (used to actually mutate state - sync commits, create stacks/PRs/users, trigger deploys) resolves the target repository from a *different* field of that same body. This breaks the intended binding "organization whose secret verified the signature == repository that gets written to."

### Finding Description
`verify_signature` computes the organization to check against like this: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')`, falling back to `params.dig('organization', 'login')` - both attacker-supplied fields in the raw JSON body. `Shipit.github(organization: repository_owner)` then looks up that organization's app config and its `webhook_secret`: [3](#0-2) 

Signature verification itself: [4](#0-3) 

Note `return true unless webhook_secret` - if the organization resolved from the payload has no `webhook_secret` configured (a supported, documented configuration, e.g. `docs/setup.md`/`config/secrets.development.shopify.yml` show `webhook_secret:` can be left blank), verification is unconditionally bypassed for that request, regardless of any signature header sent.

Meanwhile, once inside `create`, every handler resolves the concrete repository/stack to act on from a *different* field, `repository.full_name`, not from `repository.owner.login`: [5](#0-4) 

For example `PushHandler` uses `stacks` (derived from `repository.full_name`) to sync commits/trigger deploy jobs: [6](#0-5) 

and `PullRequest::OpenedHandler` independently re-derives the repository from `params.repository.full_name` to create/mutate review stacks and PRs: [7](#0-6) 

So the equality the design relies on is: `organization used to fetch webhook_secret (repository.owner.login / organization.login) == organization that owns repository.full_name`. GitHub itself enforces this equality because it always sends both fields consistently and signs the whole body. But Shipit's own trust boundary does not enforce it: an attacker who can get any single request past `verify_signature` (trivially possible for any organization configured with a blank `webhook_secret`, which the docs explicitly support) can set `repository.full_name` to point at a completely different, victim-owned repository that Shipit tracks, and the handlers will act on that repository's Stacks, PRs, users, and trigger `GithubSyncJob`/deploy triggers for it - none of which are bound to the organization that "authenticated" the request.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" boundary called out in scope. Concretely, an unprivileged attacker with no Shipit credentials can:
- Trigger `GithubSyncJob` for a victim stack (`PushHandler`), causing Shipit to sync arbitrary attacker-claimed `after` SHAs as the expected head, which feeds directly into deploy-triggering logic (`sync_github`/`build_deploy` in `Stack`).
- Fabricate `pull_request` events causing `PullRequest::OpenedHandler`/related handlers to create review stacks, `PullRequest` and `User` records tied to a victim's repository, using attacker-chosen `head.sha`, `user.login`, labels, etc.
- Potentially influence commit statuses / merge queue state for the victim repository via the `status`/`check_suite`/`pull_request` handlers, since none of these re-check that the authenticated organization actually owns the target repository.

This can lead to unauthorized state changes/deploll-triggering on a tracked stack the attacker does not control - matching the "unauthorized deploy" / "cross-repository writes" impact bar.

### Likelihood Explanation
Requires (a) at least one organization configured in Shipit with `webhook_secret` blank/unset (a documented, supported configuration - see `docs/setup.md` and `config/secrets.development.shopify.yml`), or (b) any other way to pass `verify_signature` for some organization. Given that, the attacker needs no further privileges - just POST a crafted JSON body to `/webhooks` with `X-Github-Event` set appropriately, `repository.owner.login`/`organization.login` set to the unsecured org, and `repository.full_name` set to the victim repository. This is a plausible operational misconfiguration explicitly permitted by the documented config format, not a purely theoretical scenario.

### Recommendation
Bind signature verification to the same repository identity the handlers act on: resolve the organization from `repository.full_name`'s owner (or an internally-known Stack/Repository record) rather than trusting `repository.owner.login`/`organization.login` in isolation, and reject requests where these fields disagree. Additionally, do not allow `verify_webhook_signature` to silently pass (`return true unless webhook_secret`) for organizations that own repositories tracked by Shipit; require a configured secret for any organization with active stacks, or fail closed instead of trusting an unsigned payload.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.yml`: `victim-org` (tracked, with `webhook_secret: <strong-secret>`) and `no-secret-org` (any org, `webhook_secret:` blank/omitted) - the latter is a documented, valid configuration.
2. POST to `/webhooks` with `X-Github-Event: push`, no valid `X-Hub-Signature` (or any arbitrary value), and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "no-secret-org" }
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: "no-secret-org")`; because that org's `webhook_secret` is blank, `verify_webhook_signature` returns `true` unconditionally, and the request passes.
4. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `stacks` from `repository.full_name = "victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for the victim's tracked stack - despite the request never having been authenticated for `victim-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-53)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end

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
```
