### Title
Cross-organization webhook forgery via unbound `repository.owner.login` (signature scope) vs `repository.full_name` (action target) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using one field of the JSON body (`repository.owner.login`, falling back to `organization.login`), while every webhook `Handler` (and thus every downstream state mutation) locates the target `Repository`/`Stack`/`Commit` using a *different*, independently-controlled field of the same body (`repository.full_name`, `sha`, etc.). In a multi-organization Shipit deployment, these two fields are never cross-validated, so a party who legitimately controls the webhook secret for *any one* configured organization can forge events that are verified as "belonging" to their own org but that actually target and mutate state for a completely different, victim organization's repository/stack.

### Finding Description
The controller resolves which GitHub App/secret to use for signature verification from the payload itself: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`verify_webhook_signature` only checks that the raw body HMACs correctly under the secret configured for whatever organization `repository_owner` names: [3](#0-2) 

Meanwhile, every handler resolves the actual repository/stack to mutate from a **separate** field, `repository.full_name`: [4](#0-3) 
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler` uses this to trigger a resync of a stack from a payload-controlled `after` sha: [5](#0-4) 

More critically, the `status` webhook path writes a `Status` record whose fields come directly from the payload (`state`, `target_url`, `context`, `description`) against a commit located by `sha`, as shown by the test asserting the created `Status` mirrors payload content verbatim: [6](#0-5) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name`/`sha` (used to pick the record being written) are two unrelated keys in the same attacker-supplied JSON body, and Shipit explicitly supports multiple, independently-secreted organizations in one instance (see the multi-org secrets example and `Shipit.github(organization:)` lookup): [7](#0-6) [8](#0-7) 

an attacker who legitimately administers Organization A (and therefore knows/controls Org A's own `webhook_secret`, since a GitHub App owner sets this value themselves) can send a request to Shipit's `/github_webhooks` endpoint with:
- `repository.owner.login` = `"OrgA"` (so `verify_signature` selects Org A's secret, which the attacker knows and can HMAC correctly)
- `repository.full_name` = `"OrgB/victim-repo"`, `sha` = a real commit sha belonging to Org B's stack, `state` = `"success"`, `context` = a status context required by Org B's `shipit.yml`

The forged, correctly-signed-for-Org-A payload passes `verify_signature`, but the `StatusHandler` (reached identically to `PushHandler`, both inheriting `Handler#stacks`/`#repository_name`) writes the fabricated success status onto Org B's real commit.

### Impact Explanation
This binding break — "organization that authenticated" (Org A, via its own secret) vs. "repository that is written" (Org B, via `full_name`/`sha` in the same body) — allows an attacker who controls only one configured organization to inject arbitrary CI status/check data into an unrelated organization's commits. Fabricated "success" statuses satisfy `MergeRequest#all_status_checks_passed?` and `Stack#deployment_checks_passed?`, which gate `ProcessMergeRequestsJob#perform` → `MergeRequest#merge!`: [9](#0-8) [10](#0-9) 

This can cause Shipit to auto-merge a pull request into a victim organization's repository whose CI never actually passed — an unauthorized merge, matching the required Critical-impact category (unauthorized merge) even though the attacker never held credentials, a session, or write access to the victim organization/repository.

### Likelihood Explanation
Requires the attacker to legitimately administer at least one GitHub organization already configured in the same shared Shipit instance (multi-org support is a documented, first-class feature: `secrets_double_github_app.yml`, `Shipit.github(organization:)`), and requires the victim repository/stack to already exist in that same Shipit instance with `merge_queue_enabled` and required-status gating configured. This is plausible for any Shipit deployment shared across multiple teams/orgs (a common setup this engine explicitly supports), and needs no compromise of the victim's own credentials, webhook secret, or GitHub permissions — only a correctly-crafted HTTP POST using the attacker's own legitimate secret.

### Recommendation
After selecting `github_app` via `repository_owner` for signature verification, re-derive the same organization from `repository.full_name` (and any other identity field consumed by handlers, e.g. `organization.login` for membership events) and reject the webhook (422) if they don't match. Alternatively, pass the already-verified `repository_owner`/org down to `Handler#stacks`/`#repository_name` and scope repository/commit lookups to that verified organization, so no field outside the HMAC-bound organization can be used to select the mutated record.

### Proof of Concept
1. Attacker is the legitimate admin of `OrgA`, a GitHub organization configured in the shared Shipit instance with its own `webhook_secret_A`.
2. `OrgB` (victim) is a separate organization configured in the same instance, with a stack `OrgB/victim-repo` that has `merge_queue_enabled: true` and requires status context `ci/tests`.
3. Attacker crafts a `status` event JSON body:
   ```json
   {
     "sha": "<real head sha of an open PR on OrgB/victim-repo>",
     "state": "success",
     "context": "ci/tests",
     "target_url": "https://attacker.example/fake",
     "description": "forged",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_A, raw_body)>` using their own known `webhook_secret_A`.
5. POST to `/github/webhooks` with `X-Github-Event: status`. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and the signature validates successfully.
6. `Shipit::Webhooks.for_event('status')` handler resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and creates/updates a `Status` row with `state: "success"`, `context: "ci/tests"` on the named commit — despite the request never touching Org B's real webhook secret.
7. `ProcessMergeRequestsJob` subsequently observes `all_status_checks_passed?` as true for the corresponding pending `MergeRequest` and calls `merge_request.merge!`, merging the PR in `OrgB/victim-repo` without its real CI ever passing.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** test/unit/shipit_test.rb (L11-22)
```ruby
    test ".github uses indifferent access to search through the Github applications" do
      secrets = ActiveSupport::OrderedOptions.new
      secrets.merge!(YAML.load_file('test/dummy/config/secrets_double_github_app.yml'))
      secrets.deep_symbolize_keys!
      Shipit.stubs(:secrets).returns(secrets)
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'OrgOne'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgOne))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'orgone'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :orgone))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgTwo))
      Shipit.unstub(:secrets)
    end
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L1-34)
```ruby
# frozen_string_literal: true

module Shipit
  class ProcessMergeRequestsJob < BackgroundJob
    include BackgroundJob::Unique
    on_duplicate :drop

    queue_as :default

    def perform(stack)
      merge_requests = stack.merge_requests.to_be_merged.to_a
      merge_requests.each do |merge_request|
        merge_request.refresh!
        merge_request.reject_unless_mergeable!
        merge_request.cancel! if merge_request.closed?
        merge_request.revalidate! if merge_request.need_revalidation?
      end

      return false unless stack.allows_merges?

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
      end
    end
  end
end
```
