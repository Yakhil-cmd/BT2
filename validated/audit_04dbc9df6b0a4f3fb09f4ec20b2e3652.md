Confirmed: Shipit supports multi-organization GitHub App configuration, where `Shipit.github(organization:)` looks up per-organization config (including a distinct `webhook_secret` per org) keyed by the organization name [1](#0-0) . This is exactly the "organization that authenticated versus the repository that is written" binding the rules call out, and it is broken in `WebhooksController`.

### Title
Webhook signature verification uses an attacker-controlled organization key while handlers act on an unverified repository field, breaking the (authenticated-org = written-repository) binding - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which per-organization `webhook_secret` to validate the HMAC signature against by reading `repository_owner`/`organization.login` directly out of the **unverified** JSON body, before the signature has been checked. The handler that subsequently mutates state (e.g. `PushHandler`) resolves the target `Repository`/`Stack` using a **different** field of the same unverified payload (`repository.full_name`). Nothing ties these two fields together or re-validates that the org whose secret validated the signature actually owns the repository being written to.

### Finding Description
`verify_signature` computes `repository_owner` from the raw, unauthenticated payload and uses it to select the GitHub App/secret to check the signature against: [2](#0-1) [3](#0-2) 

`Shipit.github(organization:)` looks up a distinct config (including `webhook_secret`) per organization key when multiple GitHub Apps/orgs are configured: [1](#0-0) 

If the HMAC check passes, `create` dispatches the entire unverified `params` (JSON body) to the registered handlers for the event: [4](#0-3) 

Handlers such as `PushHandler`/`Handler#stacks` then resolve the affected `Repository`/`Stack` using `payload.dig('repository', 'full_name')` — a completely separate field from the one used to select the signing secret: [5](#0-4) [6](#0-5) 

In a single-organization deployment this is not exploitable because there is only one secret. But when Shipit is configured with multiple organizations/GitHub Apps (each with its own `webhook_secret`, as supported by `github_app_config`/`TOP_LEVEL_GH_KEYS`) [7](#0-6) , an attacker who knows (or can obtain, e.g. from a public/less-sensitive org they participate in) the webhook secret for **organization A** can craft a payload where `organization.login`/`repository.owner.login` = `A` (so the signature check passes with A's secret) but `repository.full_name` = `B/some-repo` (a completely different, more sensitive repository/org managed by the same Shipit instance). The signature only proves the payload was signed by org A's secret; it proves nothing about org B. Since the handler trusts `repository.full_name` unconditionally, this breaks the equality: **(organization that authenticated) == (repository that is written)**.

### Impact Explanation
This crosses an authentication boundary between tenants/organizations hosted by the same Shipit instance. An attacker who compromises or knows only a low-value organization's webhook secret can forge webhook events (`push`, `pull_request`, `status`, `check_suite`, `membership`) that get processed as if they came from a different, unrelated organization/repository. Depending on the handler this can trigger `GithubSyncJob` (rewriting commit history state used to decide what gets deployed), fake CI `status`/`check_suite` results that make otherwise-undeployable commits appear deployable, or membership/team changes — i.e. cross-repository writes and influence over deploy eligibility for a repository the attacker does not control. This matches the "Critical: cross-repository writes / unauthorized deploy" impact category.

### Likelihood Explanation
Likelihood is Medium: it requires (a) the Shipit instance to be configured for multiple organizations with independent webhook secrets (a documented, supported configuration — see `secrets_double_github_app.yml` test fixture and `TOP_LEVEL_GH_KEYS`) [7](#0-6) , and (b) the attacker to possess a valid webhook secret for at least one configured organization (e.g. their own org onboarded into the same Shipit instance). No repository write access, Shipit session, or API token is required — only knowledge of one org's webhook secret, which is a materially weaker credential than the target repository's own secret.

### Recommendation
After signature verification succeeds, re-derive/verify that the `organization`/`repository.owner.login` used to select the signing secret matches the `repository.full_name` that handlers will act on, and reject the request if they diverge. Alternatively, bind the verified organization identity into the payload passed to handlers (rather than re-parsing the raw untrusted JSON for repository resolution), so a single verified field is used both for authentication and for authorization of which repository/stack may be mutated.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (supported per `github_app_config`).
2. As an attacker with legitimate access to `org-a`'s webhook secret (e.g., because they administer a repo under `org-a` that is also onboarded to this Shipit instance), craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": { "full_name": "org-b/victim-repo", "owner": { "login": "org-a" } }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(org-a's webhook_secret, body)>`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner` = `org-a` (from `repository.owner.login`), fetches `org-a`'s GitHub App/secret, and the signature check passes.
6. `PushHandler#stacks` resolves repositories via `payload.dig('repository','full_name')` = `org-b/victim-repo`, triggering `stack.sync_github(expected_head_sha: ...)` for a stack the attacker does not control, using only `org-a`'s credentials.

### Citations

**File:** lib/shipit.rb (L63-63)
```ruby
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
