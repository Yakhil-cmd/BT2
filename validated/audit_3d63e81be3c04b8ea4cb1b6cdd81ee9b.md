### Title
Webhook signature is verified against the organization derived from an untrusted payload field, but the repository acted upon is read from a different, unchecked payload field, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) . Once the signature check passes, the handler pipeline (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`) resolves the target repository/stack from a completely separate payload field, `payload.dig('repository', 'full_name')` [2](#0-1) . Nothing ties `full_name`'s owner segment back to the `repository_owner` value that was actually verified. Because both fields live inside the same attacker-controlled JSON body, a party who legitimately controls one organization's webhook secret (a distinct, per-organization secret in Shipit's multi-tenant GitHub config, `Shipit.github(organization:)` / `github_app_config`) [3](#0-2)  can forge a payload whose `repository.owner.login`/`organization.login` matches their own org (so the signature check succeeds against their own secret) while `repository.full_name` names a repository belonging to a different organization onboarded to the same Shipit instance.

### Finding Description
`verify_signature` treats "the organization whose secret validated this HMAC" as if it were "the organization this event is about," but the two are read from independent, unauthenticated JSON fields of the same request body:
- Authenticated organization: `params.dig('repository','owner','login')` or `params.dig('organization','login')` [4](#0-3) 
- Repository actually acted upon: `payload.dig('repository','full_name')`, used by every handler to resolve `Repository.from_github_repo_name(repository_name)` and thus the `Stack` to mutate [5](#0-4) 

There is no assertion that the owner segment of `full_name` equals `repository_owner`. The signature only proves "the sender knows the secret configured for `repository_owner`'s GitHub App entry"; it proves nothing about which repository the rest of the payload references. Any principal holding a valid per-organization webhook secret in this multi-tenant configuration (`secrets.github[org][:webhook_secret]`) can therefore submit a signed-for-their-org payload whose `repository.full_name` targets a different org's/repo's stack that is also configured on the same Shipit deployment, and every handler for that event (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.) will process it as if it legitimately originated from GitHub for that other repository.

### Impact Explanation
This breaks the binding "organization that authenticated == repository/stack that is written," which is explicitly one of the deployment-trust bindings in scope. Concrete consequences observed in the handler set:
- `push` events enqueue `GithubSyncJob` for the targeted stack, driving Shipit's internal state of commits/deploy eligibility for a repository outside the attacker's authenticated organization [6](#0-5) .
- `status` events create `Status` records against arbitrary commits of a foreign stack, which downstream feeds deploy/merge-readiness decisions [7](#0-6) .
- `check_suite` enqueues `RefreshCheckRunsJob` for a foreign stack [8](#0-7) .

Since these jobs run using Shipit's own installation-level GitHub credentials for the targeted organization (not the attacker's), an attacker can pollute status/check state and trigger sync/merge-adjacent workflows for repositories they do not own, i.e., cross-repository writes through the app's own GitHub credentials, satisfying the Critical impact bar.

### Likelihood Explanation
Exploitation requires the attacker to already be a legitimate holder of one organization's webhook secret in a multi-tenant Shipit deployment (i.e., they configured/own that organization's Shipit GitHub App entry) — no privileged Shipit session, `ApiClient` token, or the *target* organization's secret is needed. This is a realistic unprivileged-attacker path specifically in multi-org (`TOP_LEVEL_GH_KEYS`-keyed) configurations where multiple, mutually distrusting organizations are onboarded to one Shipit instance [9](#0-8) . The crafted payload is trivial to construct (mismatched `repository.owner.login` and `repository.full_name`) and nothing in `verify_signature` or the handler layer rejects the inconsistency.

### Recommendation
After verifying the HMAC signature, re-derive `repository_owner` strictly from the same field the handlers use (`repository.full_name`'s owner segment) and require it to equal the organization whose secret validated the signature, rejecting the request (422) on mismatch. Alternatively, pass the verified `repository_owner` explicitly into the handler pipeline and have `Handler#stacks` scope repository resolution to that verified organization instead of trusting `repository.full_name` in isolation.

### Proof of Concept
1. Attacker legitimately administers `attacker-org`, which is configured in Shipit's multi-tenant `secrets.github` with its own `webhook_secret` (`S_attacker`).
2. Attacker crafts a `push` (or `status`/`check_suite`) webhook JSON body:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "after": "<any sha>"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC(S_attacker, raw_body)>` using their own known secret.
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and the signature check passes because it was signed with `S_attacker` [10](#0-9) .
5. `create` then runs `Shipit::Webhooks.for_event('push').each { |handler| handler.call(params) }`; the push handler resolves the target stack via `payload.dig('repository','full_name')` == `"victim-org/victim-repo"` [2](#0-1)  and enqueues `GithubSyncJob` for `victim-org/victim-repo`'s stack, even though the signature only proves control of `attacker-org`'s secret.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L21-38)
```ruby
        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** test/controllers/webhooks_controller_test.rb (L23-32)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
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
```

**File:** test/controllers/webhooks_controller_test.rb (L75-83)
```ruby
    test ":check_suite with the target branch queues a RefreshCheckRunsJob" do
      request.headers['X-Github-Event'] = 'check_suite'

      body = JSON.parse(payload(:check_suite_master)).to_json
      assert_enqueued_with(job: RefreshCheckRunsJob) do
        post :create, body:, as: :json
        assert_response :ok
      end
    end
```
