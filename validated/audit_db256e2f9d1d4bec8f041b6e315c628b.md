### Title
Cross-organization webhook signature confusion allows spoofed events against unrelated repositories - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit.github(organization:)` supports a multi-tenant configuration where each GitHub organization has its own `webhook_secret` [1](#0-0) . The webhook signature check picks which organization's secret to verify against using `repository.owner.login`/`organization.login` from the *unverified* JSON body, while the handlers that actually mutate state (find the `Stack`/`Repository`/`PullRequest` to act on) key off the separate `repository.full_name` field from that same body [2](#0-1) [3](#0-2) . These two fields are never cross-checked against each other.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to validate the HMAC signature with based on `repository_owner`, computed as:
```ruby
params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
``` [4](#0-3) 

This value is then used to fetch the correct `webhook_secret` via `Shipit.github(organization: repository_owner)` → `github_app_config(organization)` [1](#0-0) , and the raw request body is verified against *that* organization's secret only [5](#0-4) .

Once the signature check passes, `create` dispatches the whole (already-parsed) payload to handlers [6](#0-5) . Every handler, however, resolves the target `Repository`/`Stack` using a *different* field: `payload.dig('repository', 'full_name')` [3](#0-2) , then looks it up with `Repository.from_github_repo_name`, which splits on `/` to get `owner`/`name` [7](#0-6) .

Because `repository.owner.login` (used for signature routing) and `repository.full_name` (used for the actual DB lookup/action) are independent JSON fields inside the same unsigned-until-verified body, an attacker who legitimately controls a GitHub App installation for **any one organization configured in Shipit** (and thus knows/can trigger delivery of a validly-signed webhook for that org, e.g. via `push`, `pull_request`, `status`) can craft/replay a payload where:
- `repository.owner.login` = `OrgA` (their own org — signature validates against `OrgA`'s `webhook_secret`)
- `repository.full_name` = `OrgB/some-repo` (an arbitrary, unrelated repository/stack that OrgA has no access to)

The signature check only proves "this body was signed by *some* org's secret consistent with the `owner.login` field it contains" — it does not prove that `repository.full_name` actually belongs to that organization. This breaks the intended binding: *organization that authenticated == repository that is written*.

### Impact Explanation
This lets an attacker with a valid webhook secret for one configured organization forge `push`, `pull_request`, or `status` events that are attributed to and acted upon a completely different organization's repositories/stacks — e.g. triggering `stack.sync_github(expected_head_sha:)` [8](#0-7) , mutating `PullRequest` records, or creating/unarchiving `ReviewStack`s [9](#0-8)  for a repository outside the attacker's authorized scope. This is a cross-repository/cross-organization write triggered without the target organization's actual GitHub webhook secret, matching the report's core pattern of an unchecked binding between the field used to establish trust and the field the system actually acts on.

### Likelihood Explanation
Requires the attacker to control at least one legitimate organization/app configuration already registered in Shipit's multi-org `secrets.github` config (i.e., to be a real tenant of the Shipit instance capable of triggering a validly-signed delivery). This is not a fully anonymous, zero-credential attack; it depends on a multi-tenant Shipit deployment where multiple orgs each hold their own `webhook_secret`, and one org's holder acting maliciously toward another org's data.

### Recommendation
After verifying the HMAC signature, cross-validate that `repository.owner.login` (or `organization.login`) used to select the signing secret matches the owner segment of `repository.full_name` before dispatching to handlers, rejecting the request (422) on mismatch.

### Proof of Concept
1. Shipit is configured with per-organization GitHub Apps: `OrgA` and `OrgB`, each with distinct `webhook_secret`s [10](#0-9) .
2. Attacker controls `OrgA`'s GitHub App/webhook secret (legitimately, as OrgA's admin).
3. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-controlled sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
4. Attacker signs this body with `OrgA`'s `webhook_secret` and sends it to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `OrgA`, fetches `OrgA`'s secret, and the signature validates [11](#0-10) .
6. `PushHandler#process` resolves the target via `repository_name` = `payload.dig('repository','full_name')` = `"OrgB/victim-repo"`, and calls `stack.sync_github` on OrgB's stacks [8](#0-7) [3](#0-2) , despite the signature never being validated against OrgB's secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
