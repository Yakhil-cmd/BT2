Confirmed: this deployment supports multi-organization GitHub App configuration, where `Shipit.github(organization:)` selects a distinct `webhook_secret` per organization key in `secrets.github` [1](#0-0) . The webhook signature check in `WebhooksController#verify_signature` picks which organization's secret to verify against using `repository_owner`, which is read straight out of the untrusted JSON body (`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`) [2](#0-1) . Crucially, HMAC verification covers the entire `raw_post`, but nothing cross-checks that `repository.owner.login` (used to pick the secret) is consistent with `repository.full_name` (used later to resolve the actual `Stack`/`Repository`) [3](#0-2) [4](#0-3) .

### Title
Webhook signature verification keys off `repository.owner.login`, not the `repository.full_name` actually acted on - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App / `webhook_secret` used to validate `X-Hub-Signature` based on `repository.owner.login` (or `organization.login`) taken from the unauthenticated JSON payload, then hands the *same* payload to handlers that instead resolve the target `Repository`/`Stack` from `repository.full_name`. Because the HMAC only proves "whoever crafted this exact byte string knows organization A's webhook secret," and nothing enforces that A's login is the owner prefix embedded in `full_name`, an attacker who is a legitimate GitHub App owner/admin of one organization tracked by this Shipit instance (and thus knows that org's `webhook_secret`) can forge a payload whose `owner.login` is their own org (so their own key verifies) but whose `repository.full_name` names a *different* organization's repository also tracked by the same Shipit instance.

### Finding Description
`verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) .

`Shipit.github` supports a multi-org secrets schema, looking up a distinct `webhook_secret` per organization key configured under `secrets.github` [1](#0-0) .

Downstream, every event handler (`PushHandler`, `PullRequest::*Handler`, etc.) ignores `repository.owner.login`/`organization.login` entirely and instead resolves the affected `Repository`/`Stack` using `repository.full_name`, split naively on `/`:
```ruby
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [4](#0-3) , invoked via `Handler#stacks`/`#repository_name` (`payload.dig('repository', 'full_name')`) [3](#0-2)  and in each PR handler (e.g. `Shipit::Repository.from_github_repo_name(params.repository.full_name)`) [5](#0-4) .

The equality that should hold but does not:
`organization used to select webhook_secret for signature verification == owner of the repository the handlers actually act on`.
Before the analog PR fix (i.e. as currently implemented), the controller trusts `owner.login`/`organization.login` for key selection while the business logic trusts the independent `full_name` field for repository resolution — both fields come from the same unauthenticated JSON body and are never cross-validated.

### Impact Explanation
An attacker who legitimately controls the GitHub App / webhook secret for Organization A (a real, valid Shipit-tracked org) can send a POST to `/webhooks` with a valid signature computed over a payload where `owner.login` = "A" but `repository.full_name` = "B/some-repo" (Organization B, a different org also onboarded to this same Shipit instance). Verification passes because it only checks "signed by A's secret," and then `PushHandler#process` will call `stack.sync_github(expected_head_sha: params.after)` on B's stack [6](#0-5) , or a PR handler can archive/unarchive or provision review stacks for B's repository [7](#0-6) . This is a cross-organization/cross-repository write triggered without any credential belonging to the victim organization, matching the "Critical: cross-repository writes / unauthorized deploy" impact bar.

### Likelihood Explanation
Requires the attacker to be an authenticated owner of a distinct GitHub organization/App that is independently onboarded onto the same shared Shipit instance (multi-tenant `secrets.github` config) — a legitimate, low-privilege position relative to any other tenant, not requiring compromise of the victim's secret, `GITHUB_TOKEN`, or any Shipit session. Any multi-org Shipit deployment (which the engine explicitly supports via `github_organizations`/`github_app_config`) is exposed.

### Recommendation
In `WebhooksController#verify_signature` and in each `Webhooks::Handlers::Handler`, resolve the repository/stack using the *same* owner value that was used to select the verification secret (or, conversely, verify that `repository.full_name`'s owner segment matches `repository_owner`/`organization.login` before dispatching to handlers). Reject the webhook if the two disagree.

### Proof of Concept
1. Shipit instance configured with two tenant orgs, `A` and `B`, each with its own `webhook_secret` under `secrets.github` [1](#0-0) , both with repositories tracked as `Stack`s.
2. Attacker, an admin of org `A`'s GitHub App, knows `A`'s `webhook_secret`.
3. Attacker crafts a `push` payload: `{"ref": "refs/heads/master", "after": "<attacker sha>", "repository": {"owner": {"login": "A"}, "full_name": "B/victim-repo"}}`.
4. Attacker computes `X-Hub-Signature` as `sha1=HMAC(A_secret, raw_body)` and POSTs to `/webhooks`.
5. `verify_signature` selects `Shipit.github(organization: "A")` and successfully verifies the signature [8](#0-7) .
6. `PushHandler` resolves `Repository.from_github_repo_name("b/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker sha>")` on org `B`'s stack [6](#0-5) , causing Shipit to sync/deploy against a ref chosen by the attacker for a repository they do not own.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-68)
```ruby
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
