### Title
Signature verified against `repository.owner.login`'s org while stack mutation uses unrelated `repository.full_name` — cross-org push forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to validate the HMAC against using `params.dig('repository','owner','login')`, while `Webhooks::Handlers::Handler#stacks` (used by `PushHandler#process`) resolves which `Repository`/`Stack` to mutate using the entirely independent `payload.dig('repository','full_name')`. Nothing in the request pipeline enforces that these two attacker-supplied JSON fields refer to the same organization, so a signature valid for org A's webhook secret can be replayed with `repository.full_name` pointing at org B's tracked repo.

### Finding Description
Binding claimed: `Shipit.github(organization: params.dig('repository','owner','login')) == Shipit.github(organization: full_name.split('/').first)`. This does not hold.

- `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` comes from `params.dig('repository','owner','login')` (or `params.dig('organization','login')`), then checks `github_app.verify_webhook_signature(signature, raw_post)` — the HMAC is checked against that specific org's `webhook_secret`. [1](#0-0) 

- `Handler#stacks`/`#repository_name` resolves the target `Repository` (and therefore `Stack`) purely from `payload.dig('repository', 'full_name')`, via `Repository.from_github_repo_name`, which splits `owner/name` and does a DB lookup — completely disconnected from `repository_owner` used above. [2](#0-1) [3](#0-2) 

- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack of that resolved repository matching the pushed branch — a real, sensitive write/read-triggering action against GitHub. [4](#0-3) 

- `Shipit.github` and `github_app_config` support a genuine multi-tenant configuration keyed by organization name, each with its own independently-configured `webhook_secret` (`github_config[organization.downcase.to_sym]`), confirming that different orgs on the same Shipit instance can have different, independently-known secrets. [5](#0-4) 

Attack: attacker administers "attacker-org", which is a legitimate but separately-configured org on this multi-tenant Shipit instance, and therefore knows `webhook_secret` for `attacker-org` (they set it up when onboarding their own GitHub App/webhook to this shared Shipit deployment). They POST to `/webhooks` with header `X-Github-Event: push`, a body where `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`, and `X-Hub-Signature` computed with the `attacker-org` webhook secret over the raw body. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against that org's own secret — it never checks that `victim-org` matches `attacker-org`. The request then proceeds to `Shipit::Webhooks.for_event('push')`, and `PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github` on the matching victim stack.

Existing guards do not catch this: `drop_unhandled_event` only checks event name; `check_if_ping` is irrelevant; the `ExplicitParameters` schema for `PushHandler` only requires `ref` and `after`, not any consistency between `repository.owner.login` and `repository.full_name`; there is no model validation tying the two fields together at the controller/handler layer.

### Impact Explanation
An attacker who legitimately controls one org onboarded to a shared/multi-tenant Shipit instance can forge webhook events that appear to originate from any other tracked repository/org on that instance, causing `PushHandler` to invoke `stack.sync_github` (fetch and record the victim's GitHub state, potentially triggering downstream auto-deploy flows) for a repository they do not own. This is a cross-repository/cross-tenant mutation triggered by an unauthenticated (as far as the target org is concerned) payload — matching the "Critical: payload for one repository mutating another's stack" category. It is repeatable against any tracked victim repository whose `owner/name` the attacker can guess or observe (repo full names are typically public), for every push-like/handler event.

### Likelihood Explanation
This requires a Shipit deployment that hosts multiple organizations with distinct, independently-configured GitHub App webhook secrets (the multi-tenant `github_app_config` scheme) — a config path this engine explicitly documents and supports. The attacker needs no privileged Shipit role, no session, no API token, and no secret belonging to the victim org — only knowledge of their own org's webhook secret (which they legitimately hold as the party who configured that org's integration), and the victim's public `owner/repo` name. Cost is a single crafted HTTP POST; it is fully repeatable and requires no timing race or interaction with GitHub.

### Recommendation
In `WebhooksController#verify_signature` and/or `Handler#stacks`, require that the organization used to select the webhook secret matches the owner segment parsed from `repository.full_name` (and/or the `Repository#owner` of whatever record is ultimately resolved) before processing; reject the request if they diverge. Alternatively, resolve the target `Repository` first, verify against `Shipit.github(organization: repository.owner)` for that same resolved record, rather than trusting the payload's `repository.owner.login` field independently from `repository.full_name`.

### Proof of Concept
Minitest plan for `test/controllers/webhooks_controller_test.rb` style test (illustrative, not run):
```ruby
test "signature valid for attacker org cannot mutate a victim-org stack via mismatched full_name" do
  victim_stack = shipit_stacks(:shipit) # owner: 'shopify' per fixtures
  attacker_org = 'attacker-org'
  attacker_secret = 'attacker-secret'

  Shipit.stubs(:github_app_config).with(attacker_org).returns(webhook_secret: attacker_secret)
  # Simulate multi-tenant config resolving successfully for attacker's own org
  Shipit.stubs(:github_default_organization).returns(attacker_org)

  body = {
    ref: 'refs/heads/master',
    after: 'deadbeef',
    repository: { owner: { login: attacker_org }, full_name: victim_stack.repository.github_repo_name }
  }.to_json

  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', attacker_secret, body)

  request.headers['X-Github-Event'] = 'push'
  request.headers['X-Hub-Signature'] = signature

  # Equality claimed to hold: verifying_org (attacker_org) == mutated_repository_org (victim owner)
  assert_not_equal attacker_org, victim_stack.repository.owner

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: 'deadbeef']) do
    post :create, body:, as: :json
  end
  assert_response :ok
end
```
This asserts the two sides of the binding (`verifying_org` vs `mutated_repository_org`) are unequal yet the victim `Stack` is still synced — demonstrating the vulnerability.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
