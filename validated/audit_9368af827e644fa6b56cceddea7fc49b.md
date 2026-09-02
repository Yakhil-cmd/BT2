### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but the event is dispatched using the repository resolved from a separate, independently-forgeable `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App / HMAC secret to verify the inbound payload against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login')` (or `organization.login`) [1](#0-0) . Once that HMAC check passes, the full raw `params` hash is forwarded unmodified to every registered handler via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [2](#0-1) . Handlers, however, do not resolve the target `Repository`/`Stack` from `repository.owner.login`; they use `payload.dig('repository', 'full_name')` instead, e.g. `Handler#repository_name` and `Repository.from_github_repo_name` [3](#0-2) [4](#0-3) . `full_name` is split on `/` to get the owning namespace used to find the `Repository` row, entirely independent of `repository.owner.login`.

Because `repository.owner.login` (verification key selector) and `repository.full_name` (dispatch/target selector) are two independently attacker-controllable JSON fields inside the same unsigned-until-verified POST body, this is exactly the class of bug described in the report: a value the code authenticates against (the "organization") diverges from the value the code actually acts on (the repository being written to).

### Finding Description
`Shipit` supports multiple GitHub Apps/organizations, each with its own `webhook_secret`, selected via `Shipit.github(organization:)` and `github_app_config(organization)` [5](#0-4) . The webhook signature check picks the app/secret purely from `repository_owner` extracted from the JSON body itself: `github_app = Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(...)` [6](#0-5) .

If an attacker legitimately controls (or has been granted, e.g. as a GitHub org admin) the webhook secret for one configured organization ("Org A"), they can compute a valid `X-Hub-Signature` for an arbitrary JSON body of their own construction — not one actually emitted by GitHub. They set `repository.owner.login = "OrgA"` (or `organization.login = "OrgA"`) so `verify_signature` passes against Org A's secret, while independently setting `repository.full_name = "OrgB/target-repo"`. The signature check never inspects `full_name`, and the handler dispatch never inspects `owner.login`; `Repository.from_github_repo_name("OrgB/target-repo")` resolves to a completely different repository/organization managed under Shipit [4](#0-3) .

This lets the holder of one organization's webhook secret forge events (e.g. `push`) that are processed as if they came from a different organization's repository, e.g. triggering `PushHandler#process` → `stack.sync_github(expected_head_sha: params.after)` for stacks that belong to Org B [7](#0-6) , or the pull-request handlers that resolve `repository` purely from `params.repository.full_name` to archive/unarchive review stacks, capture labels, etc. [8](#0-7) [9](#0-8) .

### Impact Explanation
This breaks the equality that should hold: `organization used to verify signature == organization owning the repository the handler acts on`. Exploiting it lets an attacker who only controls one organization's webhook secret forge and inject events that mutate state (sync github refs/commits, archive/unarchive stacks, update pull-request labels) for repositories/stacks belonging to a different, unrelated organization also hosted by the same Shipit instance — a cross-repository/cross-organization write performed without the credentials for the targeted organization. This matches the "Critical: cross-repository writes" impact bucket in scope.

### Likelihood Explanation
Requires the attacker to already possess a valid webhook secret for at least one organization configured in this Shipit instance (e.g. as an admin of their own org's GitHub App installation registered with Shipit) — no other privileged access is needed. This is a realistic scenario for the documented multi-organization deployment mode (`config/secrets.development.example.yml` shows a `github: { someorg: {...}, someothergithuborg: {...} }` shape) where different organizations' operators are not expected to be able to affect each other's repositories.

### Recommendation
Do not select the verification key from attacker-supplied payload data alone and separately resolve the mutated repository from another attacker-supplied field. Verify the signature using the same repository-resolution path used by handlers (`repository.full_name`), and additionally assert, after successful signature verification, that the resolved `Repository`'s configured owning organization equals the organization whose secret validated the signature, rejecting the webhook (422) if they disagree.

### Proof of Concept
1. Configure Shipit with two organizations, `orga` and `orgb`, each with distinct `webhook_secret`s, and a `Stack`/`Repository` `orgb/target-repo`.
2. Attacker (who administers the GitHub App for `orga`, hence knows `orga`'s `webhook_secret`) crafts a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orga" },
    "full_name": "orgb/target-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(orga_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "orga")` and validates the signature successfully [6](#0-5) .
5. `PushHandler#process` resolves the stack via `Repository.from_github_repo_name("orgb/target-repo")` and calls `stack.sync_github(expected_head_sha: ...)` [7](#0-6)  — mutating a stack owned by `orgb`, despite the attacker only holding `orga`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
