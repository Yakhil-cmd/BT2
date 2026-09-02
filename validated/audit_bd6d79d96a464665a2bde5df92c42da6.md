## Title
Webhook signature validated against the `repository.owner.login` GitHub App while the event handler mutates the repository named in `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's webhook secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`) pulled straight out of the still-unverified JSON body. Every event `Handler`, however, resolves the target `Repository`/`Stack` to act on using a *different* field of the same unverified payload: `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb`). In a multi-organization Shipit deployment (`config/secrets.*.yml` supporting per-organization `github:` blocks, see `lib/shipit.rb#github_app_config`), these two fields are never checked for consistency with each other.

### Finding Description
- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
This looks up the App config (and thus the HMAC secret) keyed by `repository.owner.login` taken from the raw, not-yet-authenticated body.
- Once the signature check passes, `create` dispatches to handlers with the same raw `params`:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
end
```
- Every handler (e.g. `PushHandler`, PR handlers) resolves the affected `Repository`/`Stack` via `Handler#stacks`/`#repository_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
`Repository.from_github_repo_name` simply splits `"owner/name"` and looks the record up — it does not require that `owner` match `repository_owner` used for the signature check.

The equality that should hold is:
`organization_that_authenticated(repository.owner.login) == organization_of_repository_acted_on(repository.full_name.split('/').first)`

Because the App/organization is selected from `repository.owner.login` but the actual write target is selected from `repository.full_name`, an attacker who can produce a validly-signed payload for **any** organization configured on the instance (e.g. an org they legitimately administer a GitHub App/webhook for) can set `repository.full_name` to `"someOtherOrg/some-repo"` while keeping `repository.owner.login` equal to their own org. The signature will verify (it is computed correctly against their own org's secret over the full raw body, including the forged `full_name`), yet the handler acts against a `Repository`/`Stack` that belongs to the other organization, e.g. triggering `GithubSyncJob`, creating `Commit`/`Status` rows, or driving continuous-deployment logic for a stack the attacker's org does not own.

### Impact Explanation
This breaks a deployment-trust binding: the identity that produced a verified signature is not the identity whose repository state is mutated. Depending on the handler this enables cross-repository writes to Shipit's DB state (commits, statuses, PR metadata, merge-queue actions) for a stack the attacker's GitHub App does not control, and — where continuous deployment is enabled on the victim stack — can influence which commit is considered "green"/deployable, indirectly triggering a deploy/rollback that the attacker does not have GitHub-level access to. This matches "cross-repository writes" / "unauthorized deploy" impact criteria. Full exploitability is bounded by which handlers are reachable for a given event and by whether the victim stack exists on the same Shipit instance, but the root cause — signature scope vs. mutation scope mismatch — is concretely reachable through `app/controllers/shipit/webhooks_controller.rb` and `app/models/shipit/webhooks/handlers/handler.rb` with no additional privilege beyond controlling one configured organization's GitHub App webhook secret.

### Likelihood Explanation
Requires a multi-org Shipit deployment (`github:` config keyed by organization, as documented in `docs/setup.md` / `config/secrets.development.example.yml`) where the attacker legitimately controls one org's GitHub App/webhook secret but wants to affect stacks belonging to another org on the same instance. This is a realistic scenario for centrally-hosted, multi-tenant Shipit installs. Likelihood is Medium: it needs the multi-org feature enabled and requires the attacker to already own a valid webhook secret for at least one configured org, but no other privilege (no Shipit session, no `ApiClient` token, no repo write access to the victim repo) is required.

### Recommendation
After signature verification, re-derive the organization from `repository.full_name` (or `repository.owner.login`) and assert it matches the organization whose secret validated the signature before dispatching to handlers — i.e. bind the field the handlers act on to the field the signature is actually verified over. Concretely, in `WebhooksController#verify_signature`/`#create`, ensure `params.dig('repository','full_name').split('/').first == repository_owner` (case-insensitively) or otherwise verify the signature against the App config resolved from `repository.full_name` rather than `repository.owner.login`.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `github.webhook_secret` (per `test/dummy/config/secrets_double_github_app.yml` pattern).
2. As an operator who controls `OrgA`'s GitHub App webhook secret, craft a `push` payload:
```json
{
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  },
  "after": "<attacker-chosen sha>",
  ...
}
```
3. Sign the raw JSON body with `OrgA`'s `webhook_secret` and send it as `X-Hub-Signature` to `POST /github/webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: 'OrgA')` and successfully verifies the signature against `OrgA`'s secret.
5. `PushHandler`/other handlers then resolve `Repository.from_github_repo_name('OrgB/victim-repo')` and act on `OrgB`'s stack (e.g., enqueue `GithubSyncJob`, record commits/statuses), even though the request was never authenticated by `OrgB`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
