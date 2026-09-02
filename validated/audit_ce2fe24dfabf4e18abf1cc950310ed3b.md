This confirms multi-tenant support: `Shipit.github(organization:)` looks up per-organization config keyed by organization name in `secrets.github`, each with its own `webhook_secret` [1](#0-0) . Now I have enough to write up the finding.

### Title
Cross-organization webhook forgery via mismatched signature-verification key and repository-lookup field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate an incoming webhook signature against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) . However, every webhook `Handler` resolves the actual target repository/stack from a *different* payload field, `payload.dig('repository', 'full_name')` [3](#0-2) . In a multi-tenant Shipit deployment (`Shipit.github(organization:)` supports one `GitHubApp`/`webhook_secret` per organization, keyed in `secrets.github`) [1](#0-0) , these two fields are never cross-checked, so a payload can pass signature verification under organization A's secret while acting on organization B's repository.

### Finding Description
The equality the engine implicitly relies on is:
`organization whose secret authenticated the signature == organization owning the repository the handler acts on`

This equality is never enforced. `verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
and verifies the raw request body against `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [4](#0-3) . This only proves "this body was HMAC-signed with organization X's `webhook_secret`" — it does not prove the body's *content* is confined to organization X's own repositories, because the HMAC key is per-organization but the payload contents (including `repository.full_name`) are entirely attacker-controlled once the attacker knows that organization's `webhook_secret`.

Every handler (`PushHandler`, `PullRequest::*Handler`, etc.) then derives the acted-upon repository independently via `repository_name = payload.dig('repository', 'full_name')` and `Repository.from_github_repo_name(repository_name)` [3](#0-2) [5](#0-4) . Nothing checks that `full_name`'s owner segment matches `repository_owner`/the key that authenticated the request.

Because a legitimate tenant organization admin who owns their own GitHub App/webhook config in Shipit necessarily knows that organization's `webhook_secret` (they configured it), they can craft an arbitrary JSON body where:
- `repository.owner.login` (or `organization.login`) = their own org, so `verify_webhook_signature` succeeds using their own secret, and
- `repository.full_name` = `"other-tenant-org/other-repo"`, an unrelated organization's repository also hosted on the same Shipit instance.

The signed body passes verification, and the dispatched handler acts on the victim organization's `Stack`/`Repository`/`PullRequest` records as if GitHub itself had sent the event.

### Impact Explanation
Depending on which webhook handler is triggered, this allows an attacker who only controls one tenant organization's GitHub App/webhook secret to manipulate another tenant's data/state without any Shipit account or GitHub access to that other organization:
- `PushHandler` can force `stack.sync_github(expected_head_sha: ...)` on a victim org's stacks/branches [6](#0-5) .
- `PullRequest::OpenedHandler`/`ClosedHandler`/`LabeledHandler` can create, archive/unarchive review stacks belonging to a victim repository [7](#0-6) [8](#0-7) .

This is a cross-tenant/cross-repository state-manipulation vector, matching the "cross-repository writes" / "unauthorized deploy" impact class, since it can trigger deploy-relevant actions (sync, provisioning, archiving) on a repository outside the attacker's authenticated organization boundary.

### Likelihood Explanation
This is only exploitable on Shipit deployments configured for **multiple organizations** sharing one Shipit instance (`secrets.github` keyed by org, per `Shipit.github_app_config`) [9](#0-8) . The attacker must be an admin/owner of one of those organizations' GitHub Apps (i.e., know that org's `webhook_secret`), which is a much lower bar than compromising the victim organization or obtaining a Shipit session/API token — no Shipit credential, GitHub access to the victim org, or interaction with the victim is required.

### Recommendation
Bind the two lookups together: after determining the verifying organization, require that `repository.full_name`'s owner segment (or `organization.login`) equals `repository_owner`, and reject the webhook (422) if they differ. Alternatively, pass the already-verified `repository_owner` into the handler dispatch path and have `Handler#stacks`/`Repository.from_github_repo_name` scope lookups to that verified owner rather than trusting `full_name` independently.

### Proof of Concept
1. Configure Shipit with two tenant orgs, `orgA` and `orgB`, each with its own GitHub App and `webhook_secret` (`secrets.github[:orga][:webhook_secret]`, `secrets.github[:orgb][:webhook_secret]`).
2. As the admin of `orgA` (who legitimately knows `orgA`'s `webhook_secret`), craft a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>`.
4. `POST /webhooks` with `X-Github-Event: push` and the above signature/body.
5. `WebhooksController#verify_signature` computes `repository_owner = "orgA"`, fetches `Shipit.github(organization: "orgA")`, and the HMAC check passes since it was signed with `orgA`'s own secret [4](#0-3) .
6. `PushHandler#stacks` resolves via `Repository.from_github_repo_name("orgb/victim-repo")` [3](#0-2) , and `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` is invoked against `orgB`'s stack — despite the attacker having no credentials for `orgB`.

### Citations

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
