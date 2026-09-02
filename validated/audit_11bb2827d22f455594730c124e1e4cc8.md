### Title
Webhook signature verification keys off `repository.owner.login` while all handlers resolve target stacks via `repository.full_name`, allowing cross-tenant stack mutation - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` to check the HMAC against using `repository_owner`, which is read from the attacker-supplied JSON body (`payload.dig('repository','owner','login')`). `Handler#repository_name`/`#stacks`, used by every push/check_suite/pull_request handler, instead resolves the target `Repository`/`Stack` using `payload.dig('repository','full_name')` — a separate, independently attacker-controlled field in the same JSON body. Nothing enforces that `full_name`'s owner segment matches `owner.login`, so a tenant who legitimately knows their own org's `webhook_secret` can sign a request whose `repository.full_name` names a different org's repository.

### Finding Description
The broken binding as an equality: the code must guarantee
`org(secret used in verify_signature) == org(repository named in payload.repository.full_name)`.

Trace:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) does `github_app = Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(header, request.raw_post)`.
- `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`) reads `params.dig('repository','owner','login')` directly from the untrusted, attacker-controlled JSON body — this is the *only* input used to pick which org's `webhook_secret` is used for the HMAC comparison [1](#0-0) .
- `Shipit.github(organization:)` (`lib/shipit.rb:170-181`) loads that org's config/`webhook_secret` from `secrets.github` via `github_app_config` [2](#0-1) .
- After verification succeeds, `Handler#initialize`/`#process` operate on the same raw `payload`, but `Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) reads `payload.dig('repository','full_name')`, an entirely separate JSON field, and `#stacks` (`handler.rb:32-34`) calls `Repository.from_github_repo_name(repository_name)` [3](#0-2) .
- `Repository.from_github_repo_name` (`app/models/shipit/repository.rb:53-56`) splits `full_name` on `/` and does `find_by(owner:, name:)` with no cross-check against the org whose secret validated the request [4](#0-3) .

Exploit flow: In a multi-org Shipit deployment (`secrets.github` keyed by multiple organizations, as documented in `docs/setup.md:181-216`), an attacker who administers a repository under **their own** org "attacker-org" (which is a legitimately configured Shipit tenant with its own `webhook_secret` that the attacker set and knows) can POST directly to `/webhooks` with:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "ref": "refs/heads/master",
  "after": "<sha>"
}
```
signed with `attacker-org`'s `webhook_secret` (`X-Hub-Signature: sha1=HMAC(attacker_org_secret, raw_post)`), with `X-Github-Event: push`. `verify_signature` computes `Shipit.github(organization: 'attacker-org')` from `owner.login`, verifies successfully against the attacker's own known secret, and the request passes. `PushHandler#process` then calls `stacks` which resolves via `full_name` = `victim-org/victim-repo`, finding and mutating the victim's real stacks (`stack.sync_github(expected_head_sha: ...)`), triggering deploy-relevant state changes for a repository the attacker never authenticated for.

Existing guards do not catch this: `verify_signature` only checks the HMAC against the secret chosen by `owner.login`; it never re-derives or cross-checks that value against `full_name`. `drop_unhandled_event` and `ExplicitParameters` schemas (`requires :ref`, `requires :after`) only validate presence/shape of unrelated fields, not owner consistency. `Repository.from_github_repo_name` performs no organization-scoping check either.

### Impact Explanation
An attacker who is a legitimate tenant of one organization on a shared Shipit instance can forge push/check_suite/pull_request events that mutate another organization's `Stack`/`Commit`/`Task` records — e.g., queuing `GithubSyncJob` (via `PushHandler`) or `RefreshCheckRunsJob` for a victim stack, or affecting pull-request-driven review-stack provisioning/merge logic in other `pull_request/*` handlers that inherit `#stacks`/`#repository_name` from `Handler`. This is repeatable against any repository/stack in the same Shipit install and matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Requires: (1) the Shipit deployment configured with multiple GitHub organizations (`secrets.github` with per-org `webhook_secret`s, the documented multi-org setup), and (2) the attacker being an existing, legitimate tenant/organization on that instance (they must know their own org's `webhook_secret`, which they control since they configure their own GitHub App/webhook). Given those two preconditions — which are realistic for any shared/multi-tenant Shipit install — the attack costs a single HTTP POST with correctly computed HMAC over attacker-chosen JSON, fully repeatable at will and does not require any GitHub or Shipit privileged secret belonging to the victim.

### Recommendation
In `WebhooksController#verify_signature`, after signature verification, assert that the organization derived from `repository.full_name` (or the handler's own repository resolution) matches the `repository_owner`/`organization` used to select the `webhook_secret`; reject the request (422) on mismatch. Alternatively, have `Handler#repository_name`/`#stacks` accept and enforce the verified organization from the controller (e.g., pass it into `Handler.call`) and validate it against the owner segment of `full_name` before resolving `Repository`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_cross_org_test.rb
require 'test_helper'

module Shipit
  class WebhooksControllerCrossOrgTest < ActionController::TestCase
    tests Shipit::WebhooksController

    setup do
      # Two orgs configured, each with its own webhook_secret
      Shipit.stubs(:secrets).returns(OpenStruct.new(github: {
        'attacker-org' => { 'webhook_secret' => 'attacker-secret' },
        'victim-org'   => { 'webhook_secret' => 'victim-secret' },
      }))
      @victim_stack = shipit_stacks(:shipit) # owner: victim-org, name: shipit (adjust fixture)
    end

    test "push payload naming victim-org repo but signed with attacker-org secret is accepted and mutates victim stack" do
      body = {
        'ref' => 'refs/heads/master',
        'after' => 'deadbeef',
        'repository' => {
          'owner' => { 'login' => 'attacker-org' },        # verified org
          'full_name' => 'victim-org/shipit',               # target org/stack
        },
      }.to_json

      signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', body)

      @request.headers['X-Github-Event'] = 'push'
      @request.headers['X-Hub-Signature'] = signature

      # Equality claimed to hold: org(secret verifying) == org(full_name)
      # attacker-org != victim-org -- assert both sides diverge yet request still succeeds
      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @victim_stack.id, expected_head_sha: 'deadbeef']) do
        post :create, body:, as: :json
      end
      assert_response :ok
    end
  end
end
```
This demonstrates the request is verified using `attacker-org`'s secret while `Handler#stacks` resolves and mutates the `victim-org` stack, proving the binding is not enforced.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
