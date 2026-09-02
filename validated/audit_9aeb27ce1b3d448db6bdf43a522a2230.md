### Title
Cross-tenant `Shipit::ReviewStack` creation via forged `repository.full_name` in `/webhooks` payload while signing with an unrelated org's `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` to validate the HMAC using `params.dig('repository','owner','login')` taken from the attacker-controlled JSON body, while `OpenedHandler#repository` looks up the target `Shipit::Repository` using the unrelated `params.repository.full_name` field from the same body. Nothing enforces that these two fields refer to the same organization, so an attacker who owns/administers any org configured on the multi-tenant Shipit host can sign a payload with their own known `webhook_secret` while setting `repository.full_name` to a victim org/repo, causing a `ReviewStack` to be created against the victim's repository.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:

`organization used by verify_signature` (`params.dig('repository','owner','login')`, from `app/controllers/shipit/webhooks_controller.rb:59-62`) **must equal** the owner segment of `params.repository.full_name` used by the handler (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:50-54`, `app/models/shipit/repository.rb:53-56`) — this equality is never checked anywhere in the request path.

Code path:
1. `WebhooksController#create` parses the raw JSON body and dispatches to handlers [1](#0-0) .
2. `verify_signature` picks the GitHub App config purely from `repository_owner`, itself read straight out of the same attacker-supplied body (`params.dig('repository','owner','login')`), and verifies the HMAC of the raw body against that app's `webhook_secret` [2](#0-1) .
3. Shipit explicitly documents and supports multiple GitHub Apps/orgs on one host, each with its own `webhook_secret`, selected by `Shipit.github(organization:)` / `github_app_config` [3](#0-2) , as shown in `docs/setup.md`'s "Using Multiple Github Applications" section and `test/dummy/config/secrets_double_github_app.yml`.
4. `OpenedHandler`'s `ExplicitParameters` schema only requires `repository.full_name`, not `repository.owner.login` [4](#0-3) , so these two fields can be set independently and inconsistently by the attacker.
5. `OpenedHandler#repository` resolves the target `Shipit::Repository` solely from `params.repository.full_name`, split on `/` [5](#0-4) [6](#0-5) .
6. If that repository has `review_stacks_enabled` and a matching `provisioning_behavior` (attacker also fully controls PR `labels` in the same forged body), `ReviewStackAdapter#find_or_create!`/`#create!` creates a `ReviewStack`, its `PullRequest`, and enqueues it for provisioning — all scoped to the victim repository [7](#0-6) .

Exploit request: attacker (owning `attacker-org`, which is configured as one of the multiple GitHub Apps on the Shipit host and whose `webhook_secret` they set/know) POSTs to `/webhooks` with `X-Github-Event: pull_request`, `X-Hub-Signature` computed as `HMAC-SHA1(attacker-org's webhook_secret, raw_body)`, and a raw body where `repository.owner.login = "attacker-org"` (to select the matching secret for verification) but `repository.full_name = "victim-org/victim-repo"` (to target the victim's tracked repository). Because the signature only proves the request bytes were signed by *some* configured org's secret — not that the payload's `repository.full_name` belongs to that org — verification passes, and the handler acts on the victim repository.

Existing guards do not catch this: `verify_signature` never compares `repository_owner` to `repository.full_name`'s owner segment; `drop_unhandled_event` only checks the event type is handled; the `ExplicitParameters` schema in `OpenedHandler` validates types/presence, not cross-field consistency; `Repository.from_github_repo_name` performs a plain `find_by` with no ownership check tying it back to the authenticating org.

### Impact Explanation
An unprivileged attacker who merely administers their own onboarded repo (Repo B) on a multi-tenant Shipit installation can force creation of a `Shipit::ReviewStack` (with its `PullRequest` record and provisioning queue entry, i.e. real deploy resources) against `victim-org/victim-repo` (Repo A), a repository they have no relationship to. This is a cross-repository write triggered by credentials belonging to an unrelated tenant — matching the Critical category "a payload for one repository mutating another's stack." It is repeatable against any tracked repository that has `review_stacks_enabled`, for every PR-opened-style event, and the blast radius spans every other tenant configured on the same multi-org Shipit host.

### Likelihood Explanation
Requires: (a) the Shipit host is configured with multiple GitHub Apps/orgs (an explicitly documented, supported configuration — `docs/setup.md` "Using Multiple Github Applications"), (b) the attacker administers at least one of those orgs/repos and therefore knows its `webhook_secret`, and (c) the victim repository is already tracked in Shipit with `review_stacks_enabled` and a `provisioning_behavior` the attacker can satisfy (trivial, since they also control the PR payload's labels). Cost to the attacker is a single crafted HTTP POST with a correctly computed HMAC using a secret they legitimately possess for their own org — no GitHub interaction or privileged Shipit credentials are needed.

### Recommendation
In `WebhooksController#verify_signature` (or in each handler before acting), after selecting the GitHub App via `repository_owner`, assert that `repository_owner` matches the owner segment parsed from `params.dig('repository', 'full_name')` (and from `params.dig('organization','login')` where applicable) before proceeding; reject with `422` on mismatch. This closes the gap between "which secret authenticated this request" and "which repository the payload claims to describe."

### Proof of Concept
Minitest plan (integration test against `WebhooksController`, no live GitHub):
1. Load `test/dummy/config/secrets_double_github_app.yml` fixture with `OrgOne` and `OrgTwo`, each with a known `webhook_secret`.
2. Create `Shipit::Repository.create!(owner: "orgone", name: "victim-repo", review_stacks_enabled: true, provisioning_behavior: :allow_all)` (Repo A, "victim").
3. Build a `pull_request` "opened" payload JSON with `repository.owner.login = "OrgTwo"` and `repository.full_name = "orgone/victim-repo"`.
4. Compute `X-Hub-Signature` as `sha1=` + `OpenSSL::HMAC.hexdigest('sha1', OrgTwo_webhook_secret, raw_body)`.
5. POST to `/webhooks` with `X-Github-Event: pull_request` and the computed signature header.
6. Assert response is `:ok` (not `422`), and assert `Shipit::ReviewStack.exists?(repository: victim_repository)` is true — i.e., a `ReviewStack` was created for `orgone/victim-repo` despite the signature having been validated against `OrgTwo`'s secret, proving `repository_owner (OrgTwo) != full_name owner (orgone)` yet the write succeeded.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-85)
```ruby
          def find_or_create!
            stack || create!
          end

          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end

          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
          end

          private

          attr_reader :params, :scope

          def action
            params.action
          end

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
```
