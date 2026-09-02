This confirms a genuine cross-organization binding mismatch when Shipit is configured for multi-organization mode (`secrets.github` keyed by organization).

### Title
Webhook signature verified against `repository.owner.login` while stack/repository lookup uses the unrelated `repository.full_name` field, allowing cross-organization push forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (or `organization.login`) in the *unverified* JSON body. `Handler#stacks` (and every event handler) independently resolves the target `Repository`/`Stack` using a different field from the same unverified body: `payload.dig('repository', 'full_name')`.

### Finding Description
In multi-organization mode, `Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization key in `secrets.github` [1](#0-0) . The controller picks that organization solely from the payload's `repository.owner.login`/`organization.login` field before the signature has been checked: [2](#0-1) 

Once the signature is accepted (using the secret belonging to whatever `repository_owner` the attacker put in the JSON), the actual event body is dispatched to handlers unmodified: [3](#0-2) 

Every handler then resolves the affected `Stack`/`Repository` from a **separate** field, `repository.full_name`, not from `repository.owner.login`: [4](#0-3) [5](#0-4) 

Nothing in the code enforces that `repository.owner.login` (used to pick the verifying secret) is consistent with `repository.full_name`'s owner segment (used to pick the acted-upon repository). Because HMAC-SHA1/256 signs the whole raw body, an attacker who legitimately controls a GitHub organization/repo configured in Shipit (and therefore knows or can trigger a validly-signed webhook payload for their own repo, e.g. via a push they make to their own repo) can craft the JSON body so that `repository.owner.login` equals their own org (making `verify_signature` pass with their own webhook secret) while `repository.full_name` names an arbitrary other organization's repository already registered in Shipit (e.g. `"other-org/other-repo"`), because the sending organization/repository (owner.login) and written-to repository (full_name) are never asserted equal — breaking the binding `verified-organization == acted-upon-repository-owner`.

This lets a validly-signed webhook for organization A trigger `PushHandler#process` (or PR handlers) against a `Stack` owned by organization B, e.g. calling `stack.sync_github(expected_head_sha: params.after)` [6](#0-5) , forging sync/status/PR events for a repository the attacker does not control, since GitHub itself never generates such an inconsistent payload but Shipit's verification logic never checks for it.

### Impact Explanation
This is a cross-organization write: an attacker holding webhook credentials only for their own configured organization can forge state-changing GitHub events (push-triggered syncs, PR-driven review-stack archive/unarchive, label-driven provisioning behavior) against a `Stack`/`Repository` belonging to a different organization in the same Shipit instance. This matches the "Critical: cross-repository writes" impact class, since it lets one org affect another org's deploy pipeline state (sync triggers, review stack archival) without any credential for the victim org.

### Likelihood Explanation
Medium/Low — requires: (1) Shipit configured with multiple organizations in `secrets.github` (multi-tenant setup, a documented supported mode) [7](#0-6) , and (2) the attacker controls at least one of the configured organizations/webhook secrets. This is realistic for shared/multi-tenant Shipit deployments serving several GitHub orgs, which is exactly the scenario `github_app_config` was built to support.

### Recommendation
1. In `Handler#stacks`/`repository_name`, and in each PR handler's `repository` method, validate that the organization segment of `repository.full_name` matches the `repository.owner.login`/`organization.login` used during signature verification (i.e., bind the same field used for `Shipit.github(organization:)` lookup to the field used for stack resolution) before processing any event.
2. Alternatively, pass the verified `repository_owner` from the controller down into the handler dispatch and have `Repository.from_github_repo_name` reject/ignore any repo whose owner does not equal the verified organization.
3. Add a regression test that sends a validly-signed payload for org A with `repository.full_name` pointing to org B's registered repository and asserts the event is rejected/ignored.

### Proof of Concept
1. Configure Shipit in multi-org mode with two organizations, `org-a` (attacker-controlled, webhook secret known to attacker) and `org-b` (victim, has a registered `Stack` for `org-b/private-repo`).
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/private-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` using `org-a`'s webhook secret (which they legitimately possess) over this exact raw body, per `GitHubApp#verify_webhook_signature` [8](#0-7) .
4. POST to `/github/webhooks`. `verify_signature` computes `repository_owner = "org-a"`, fetches `Shipit.github(organization: "org-a")`, and successfully verifies the signature.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("org-b/private-repo")`, finds `org-b`'s stack, and calls `stack.sync_github(expected_head_sha: ...)` — a cross-organization action triggered with a signature that never covered `org-b`'s webhook secret.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
