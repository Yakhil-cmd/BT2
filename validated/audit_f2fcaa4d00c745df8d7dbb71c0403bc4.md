### Title
Cross-organization webhook forgery via mismatch between the organization used for signature verification and the repository used for state mutation - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to verify a webhook's HMAC signature against based on `repository.owner.login` (or `organization.login`) taken from the **same attacker-supplied JSON payload** that the signature covers. Every `Webhooks::Handlers::Handler` subclass, however, resolves the `Repository`/`Stack` to act on using an entirely separate field of that same payload: `repository.full_name`. Nothing binds these two fields together, so an attacker who legitimately controls the `webhook_secret` for *any* one GitHub organization/App configured in `Shipit.secrets.github` (a low-privilege, low-value org they administer) can forge a signed payload whose `repository.owner.login` matches their own org (to pass HMAC verification) while `repository.full_name` names a repository belonging to a completely different, unrelated organization configured on the same Shipit instance. This lets them drive Shipit's webhook handlers against a repository/stack they do not control.

### Finding Description
This mirrors the reported bug class: a verification check that is applied to one part of a payload while a different, unguarded part of the very same payload is the one that is actually acted upon — analogous to `changeFees()` checking nothing about `proposedFeeTime` while still trusting `proposedFees`. Here the binding that should hold is:

`organization that authenticated (repository.owner.login used for HMAC) == repository that is written (repository.full_name resolved to a Repository/Stack)`

`verify_signature` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` looks up per-organization app config (`webhook_secret`, etc.) keyed by exactly this attacker-controlled `repository_owner` string: [2](#0-1) 

Once the signature is valid for that organization, `Webhooks.for_event(event)` dispatches the full JSON body to every registered handler, and each `Handler` independently derives the target repository from `repository.full_name`, without ever cross-checking it against `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

The same disconnect is repeated in every pull-request handler (`opened_handler.rb`, `labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`, `closed_handler.rb`, `edited_handler.rb`, `assigned_handler.rb`, `label_capturing_handler.rb`), all of which call `Shipit::Repository.from_github_repo_name(params.repository.full_name)`: [4](#0-3) [5](#0-4) 

Because the JSON body is a single attacker-authored blob and the whole body is what the HMAC signs, an attacker who knows the `webhook_secret` for organization A (Shipit config supports multiple orgs, e.g. `secrets.development.shopify.yml` shows a `somegithuborg`/`someothergithuborg` schema) can set `repository.owner.login = "orgA"` (so `Shipit.github(organization: "orgA")`'s secret is used and the HMAC passes) while setting `repository.full_name = "orgB/victim-repo"` (an unrelated, victim organization's repository that is also registered as a `Repository`/`Stack` on the same Shipit instance). The signature check never notices the mismatch.

### Impact Explanation
This breaks the deployment-trust boundary between organizations sharing one Shipit instance: cross-repository state mutation. Depending on which handler fires:
- `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack with an attacker-chosen `after` SHA [6](#0-5) .
- `StatusHandler` writes forged CI statuses onto arbitrary commits by SHA (`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`), which can influence merge/deploy gating on the victim stack [7](#0-6) .
- `PullRequest::ClosedHandler`/`LabeledHandler`/etc. archive/unarchive review stacks belonging to the victim organization's repository [8](#0-7) .

This is an unauthorized cross-repository write against a stack/repository the attacker's organization does not own, satisfying the "cross-repository writes" Critical-impact category, and can also be leveraged toward triggering an unauthorized deploy/sync on the victim stack.

### Likelihood Explanation
Requires that: (1) Shipit is configured with the multi-organization `github:` schema so more than one organization's `webhook_secret` exists on the instance, and (2) the attacker legitimately controls one such configured organization/App (i.e., they can set/know its `webhook_secret`), and (3) a `Repository`/`Stack` for the victim organization is also registered on the same instance. This is a realistic multi-tenant deployment pattern that the engine explicitly documents and supports (`docs/setup.md`, `config/secrets.development.shopify.yml`). No repository write access, `ApiClient` token, or session is needed — only the ability to send a raw HTTP POST to `/webhooks` with a validly-signed-for-org-A payload.

### Recommendation
After computing `repository_owner` and verifying the signature, re-derive the acted-upon repository/organization strictly from the same `repository_owner`/organization value used to select the signing secret, and reject the webhook (or refuse to dispatch to handlers) if `repository.full_name`'s owner segment does not case-insensitively match `repository_owner`. Concretely, in `WebhooksController#verify_signature`, add a check such as:
```ruby
full_name_owner = params.dig('repository', 'full_name')&.split('/', 2)&.first
head(422) and return if full_name_owner && full_name_owner.casecmp(repository_owner).nonzero?
```
before dispatching to `Shipit::Webhooks.for_event(event)`.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` and `victim-org`, each with their own `webhook_secret` (multi-org schema per `docs/setup.md`/`config/secrets.development.shopify.yml`).
2. `victim-org/prod-repo` is registered as a `Repository`/`Stack` in this Shipit instance.
3. Attacker, who legitimately owns/administers the GitHub App for `attacker-org` (and thus knows its `webhook_secret`), crafts a push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/prod-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature` as `HMAC-SHA1(attacker-org's webhook_secret, raw_body)` and POSTs to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` looks up `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and validates successfully because the attacker used the correct secret for that org.
6. `PushHandler#process` uses `payload.dig('repository', 'full_name')` = `"victim-org/prod-repo"` to locate the victim's `Stack` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, mutating state on a repository the attacker never authenticated against.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
