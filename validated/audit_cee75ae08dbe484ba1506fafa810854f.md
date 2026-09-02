### Title
Webhook organization used for signature verification is attacker-controlled and decoupled from the repository the payload acts on, allowing unauthenticated forged events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on a field taken directly from the **unverified** request body, while the handlers that actually mutate stack state select their target repository from a **different** field of that same unverified body. An attacker who can name any configured GitHub organization/app that has no `webhook_secret` set (a supported, documented configuration) can make the signature check for a *different* target repository trivially pass, then have the payload's `repository.full_name` field point at any repository/stack managed by the instance.

### Finding Description
`verify_signature` derives the organization used for verification straight from the JSON body, before the signature has been checked: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: ...)` resolves the per-organization config keyed by that same attacker-supplied value: [3](#0-2) 

Signature verification for that resolved config is a no-op whenever the resolved organization has no `webhook_secret` configured: [4](#0-3) 

This is not a hypothetical config: multiple checked-in configuration samples set `webhook_secret: # nil` for individual organizations while other organizations in the same instance have real secrets, e.g. `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`, confirming per-organization apps with a missing secret are a supported deployment shape for multi-org Shipit installations.

Meanwhile, every webhook handler determines *which repository/stack to act on* from a completely separate field of the same unverified JSON body: [5](#0-4) 

Nothing ties `repository.owner.login` (used to pick the verifying secret) to `repository.full_name` (used to pick the acted-upon `Repository`/`Stack`). An attacker crafts a single POST to `/webhooks` where:
- `repository.owner.login` (or top-level `organization.login`) = an organization configured with no `webhook_secret`.
- `repository.full_name` = `"victim-org/victim-repo"` (any repository actually managed by the Shipit instance, belonging to a *different*, properly-secured organization).

`verify_signature` resolves the no-secret org's `GitHubApp`, calls `verify_webhook_signature`, which returns `true` unconditionally (`return true unless webhook_secret`), regardless of the actual `X-Hub-Signature` header or payload content. The request is then dispatched to handlers (e.g. `PushHandler`, pull-request handlers) which resolve `victim-org/victim-repo` via `Repository.from_github_repo_name` and act on it.

This breaks the trust equality the rules describe as: *"an organization that authenticated versus the repository that is written."* The organization whose (absent) secret authorized the request is not the organization/repository whose state is mutated.

### Impact Explanation
An unauthenticated attacker who knows (or brute-forces) the name of any configured GitHub organization lacking a `webhook_secret` can forge arbitrary webhook events for any repository tracked by the Shipit instance, without possessing any GitHub credentials, App private key, or Shipit session/API token. Depending on the event type this enables, for example:
- `push` events triggering `GithubSyncJob`/`stack.sync_github` for an arbitrary tracked stack ( [6](#0-5) ), which can advance a stack's known head and interact with continuous-deployment logic.
- `pull_request` events causing review-stack provisioning/archival for arbitrary repositories ( [7](#0-6)  and closed/labeled handlers).
- `status`/`check_suite` forgery affecting commit deployability state used for gating deploys.

This crosses the "unauthorized deploy/rollback" and "cross-repository writes" impact bar defined in scope, since the write target is fully attacker-chosen and independent of the (non-existent) authentication that was actually checked.

### Likelihood Explanation
Requires only that the Shipit deployment configures at least two GitHub organizations/apps where at least one has no `webhook_secret` — a pattern explicitly present in the repo's own sample/dev/test secrets files, suggesting it is a realistic, supported configuration rather than an edge case. No credentials, tokens, or sessions are required; a single crafted HTTP POST is sufficient.

### Recommendation
- Never resolve the verifying organization from unauthenticated request content. Determine the target `Repository`/`Stack` first from a trusted source (e.g. an installation ID embedded in a verified GitHub App payload, or by requiring signature verification against every configured secret until one matches), and only then use that same resolved identity for downstream processing.
- Do not silently return `true` from `verify_webhook_signature` when `webhook_secret` is blank; instead, reject the event (or explicitly document/guard that "no secret" orgs are fully untrusted and disallow shared instances mixing secured/unsecured orgs).
- Add a consistency check that verified organization matches the `repository.owner.login`/`full_name` used downstream, rejecting mismatches.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgA` (has a real `webhook_secret`) and `OrgB` (no `webhook_secret`, matching the documented pattern in `config/secrets.development.shopify.yml`).
2. Attacker (no credentials) sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=deadbeef   # arbitrary/invalid

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgB" },
    "full_name": "OrgA/victim-repo"
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgB")`, whose `verify_webhook_signature` returns `true` because `OrgB` has no `webhook_secret` [8](#0-7) .
4. `PushHandler` resolves the stack via `repository.full_name = "OrgA/victim-repo"` [9](#0-8)  and enqueues `GithubSyncJob` for a repository belonging to the properly-secured `OrgA`, despite the forged/invalid signature.

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
