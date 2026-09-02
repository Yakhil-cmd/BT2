This confirms the mechanism: `Shipit.github(organization: repository_owner)` selects a per-organization `GitHubApp` config (with its own `webhook_secret`) using the multi-tenant schema, keyed purely off the attacker-supplied `repository.owner.login` (or `organization.login`) field in the JSON body [1](#0-0) , and the org lookup is a case-insensitive symbol hash lookup with no relation to which actual GitHub org the payload's content refers to [2](#0-1) .

### Title
Webhook signature verification is bound to an attacker-chosen organization key, not the repository the payload actually mutates - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to verify a webhook against using `repository_owner`, a value read directly out of the unauthenticated JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`) [1](#0-0) [3](#0-2) . The handlers that actually act on the payload, however, derive the target repository/stack from a *different* field of the same body: `payload.dig('repository', 'full_name')` [4](#0-3) , resolved via `Repository.from_github_repo_name` [5](#0-4) . Because these two fields are independently attacker-controlled and nothing binds them together, the "organization whose secret authenticated this request" and "the repository whose stacks get mutated" are two different, uncorrelated trust domains.

### Finding Description
In multi-tenant configuration (`Shipit.github_organizations` with more than one org key, e.g. `test/dummy/config/secrets_double_github_app.yml`), `Shipit.github(organization:)` performs a case-insensitive hash lookup of the org's config, including its own independent `webhook_secret` [6](#0-5) . `GitHubApp#verify_webhook_signature` explicitly no-ops verification when no secret is configured for that org: `return true unless webhook_secret` [7](#0-6) .

An attacker who can reach `/webhooks` (an unauthenticated, public endpoint by design) crafts a single JSON payload where:
- `repository.owner.login` (or `organization.login`) is set to an org configured on this Shipit instance **without** a `webhook_secret` — this is the value used solely to select which `GitHubApp`/secret is used for HMAC verification [3](#0-2) .
- `repository.full_name` is set to `"<other-org>/<real-repo>"`, an entirely different, actually-tracked repository/stack belonging to a *different* org that Shipit manages.

`verify_signature` passes (verification is skipped entirely because that org has no secret), yet `Handler#repository_name`/`Handler#stacks` resolve and act against the real target repository named in `full_name` [8](#0-7) . This breaks the intended binding: "organization whose signature is verified" ≡ "organization/repository the handler mutates." The equality the code implicitly (and incorrectly) assumes is `repository_owner (signature-selecting field) == full_name's owner (data-mutating field)`, but nothing enforces it.

Concretely reachable handlers that mutate state purely from `full_name`/other payload fields without any additional authorization include, for example, `push` (enqueues `GithubSyncJob`), `status` (creates commit statuses), `check_suite` (enqueues `RefreshCheckRunsJob`), and the `pull_request` family of handlers (label/merge-status changes) [9](#0-8) .

### Impact Explanation
This allows an unauthenticated network attacker to inject forged GitHub events (fake pushes, fake commit statuses, fake check-suite/pull_request events) against any repository/stack tracked by the Shipit instance, as long as at least one configured organization on that instance lacks a `webhook_secret`. Forged `status`/`check_suite` events can flip commit deployability signals that gate automatic deploys, and forged `push`/`pull_request` events can trigger sync jobs and merge/label workflows on stacks belonging to an organization the attacker does not control — an unauthorized-deploy-adjacent integrity break reachable with zero credentials.

### Likelihood Explanation
Requires only that the Shipit deployment manages more than one GitHub organization and that at least one of the configured organizations has `webhook_secret` left blank (documented as "optional" in `docs/setup.md`) [10](#0-9) . No credentials, no repository access, and no session are required — the `/webhooks` endpoint is intentionally public and unauthenticated by design [11](#0-10) .

### Recommendation
Do not select the verification secret from an attacker-controlled field that differs from the field the handlers actually act upon. Either: (1) require `webhook_secret` to be present for every configured organization and fail closed instead of `return true unless webhook_secret`, or (2) after selecting the org for verification, cross-check that `repository.full_name`'s owner matches the org actually used to verify the signature, rejecting the request otherwise.

### Proof of Concept
1. Configure Shipit with two organizations: `OrgA` (no `webhook_secret`) and `OrgB` (has `webhook_secret`, and has a tracked repository `OrgB/service`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/service" },
  "after": "<attacker-chosen-sha>",
  "ref": "refs/heads/master"
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — no valid signature is required [12](#0-11) .
4. The `push` handler resolves `repository_name` = `"OrgB/service"` and enqueues `GithubSyncJob` for `OrgB`'s real stack, entirely bypassing any authentication tied to `OrgB`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-6)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L23-83)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
    end

    test ":push does not enqueue a job if not the target branch" do
      request.headers['X-Github-Event'] = 'push'
      params = JSON.parse(payload(:push_not_master)).to_json
      assert_no_enqueued_jobs do
        post :create, body: params, as: :json
      end
    end

    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end

    test ":state with a unexisting commit respond with 200 OK" do
      request.headers['X-Github-Event'] = 'status'
      params = { 'sha' => 'notarealcommit', 'state' => 'pending', 'branches' => [{ 'name' => 'master' }] }.merge(repository_params).to_json
      post :create, body: params, as: :json
      assert_response :ok
    end

    test ":state in an untracked branche bails out" do
      request.headers['X-Github-Event'] = 'status'
      params = { 'sha' => 'notarealcommit', 'state' => 'pending', 'branches' => [] }.merge(repository_params).to_json
      post :create, body: params, as: :json
      assert_response :ok
    end

    test ":check_suite with the target branch queues a RefreshCheckRunsJob" do
      request.headers['X-Github-Event'] = 'check_suite'

      body = JSON.parse(payload(:check_suite_master)).to_json
      assert_enqueued_with(job: RefreshCheckRunsJob) do
        post :create, body:, as: :json
        assert_response :ok
      end
    end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```
