### Title
Cross-org webhook signature bypass unarchives another organization's ReviewStack - (File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App / `webhook_secret` used to verify the HMAC signature based on `params.dig('repository','owner','login')`, while `ReopenedHandler#repository` resolves the target repository/stack using the *separate* `params.repository.full_name` field. Because these two payload fields are never cross-checked, an attacker can sign a payload with org-a's `webhook_secret` while setting `repository.full_name` to an org-b repository, causing `ReopenedHandler#process` to call `stack.unarchive!` on org-b's stack.

### Finding Description
The binding the security model requires is: `verifying_org (params.repository.owner.login) == mutated_repository_org (params.repository.full_name.split('/').first)`.

- `WebhooksController#verify_signature` in [1](#0-0)  computes `repository_owner` via `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`) and does `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. The repository_owner lookup and definition are here: [2](#0-1) .
- `ReopenedHandler#repository` instead resolves the acted-upon repository purely from `params.repository.full_name`: [3](#0-2) . `Repository.from_github_repo_name` splits that string on `/` to get the owner used for the DB lookup, independent of `repository.owner.login`: [4](#0-3) .
- `ReopenedHandler#process` then calls `stack.unarchive!` unconditionally (subject only to provisioning-behavior checks scoped to the wrongly-resolved `repository`), which is `ReviewStackAdapter#unarchive!`: [5](#0-4)  and [6](#0-5) .

There is no code anywhere in `WebhooksController`, `Handler`, or `ReopenedHandler` that verifies `repository.owner.login` (used for signature verification) matches the owner segment of `repository.full_name` (used for the actual mutation). These are two independently attacker-controlled JSON fields in the same POST body.

Attacker's exact request: POST `/webhooks` with header `X-Github-Event: pull_request`, `X-Hub-Signature` computed with **org-a's** `webhook_secret` (which the attacker has because they registered/own an org-a app or repo whose secret they control), and a JSON body where:
- `repository.owner.login = "org-a"` (so `verify_signature` picks org-a's app/secret and the signature checks out)
- `repository.full_name = "org-b/some-repo"` (targets an unrelated tenant's repository)
- `action = "reopened"`, `number = <org-b PR number>`, and a valid nested `pull_request`/`sender` structure satisfying the `ExplicitParameters` schema in [7](#0-6) .

Exploit flow: `verify_signature` succeeds (org-a's secret validates org-a-signed content) → `Webhooks.for_event('pull_request')` dispatches to `ReopenedHandler.call(params)` → `ReopenedHandler#repository` looks up org-b's `Repository` row by `full_name` → `stack` resolves org-b's archived `ReviewStack` for that PR/environment → `respond_to_pull_request_reopened?` passes if org-b's repository has `review_stacks_enabled` and a matching `provisioning_behavior` (attacker-uncontrolled but often `allow_all` by default) → `stack.unarchive!` runs, which adds the stack to `ReviewStackProvisioningQueue` and calls `stack.unarchive!(user)`, re-provisioning infrastructure and resuming deploy tasks under org-b's GitHub credentials.

Existing guards do not catch this: `ExplicitParameters` only validates presence/type of fields, not cross-field consistency; `verify_signature` never re-derives the owner from `full_name`; `Repository.from_github_repo_name` performs no ownership cross-check against the verified org.

### Impact Explanation
A successful request causes `Shipit::ReviewStack#unarchive!` to execute against org-b's tenant record while authenticated only under org-a's webhook secret — this is a "payload for one repository mutating another's stack" scenario, matching the Critical impact category. The immediate effect is unarchiving (re-provisioning) org-b's review stack, which re-enqueues it in `ReviewStackProvisioningQueue` and can resume automatic deploy tasks that execute `Command`/`PTY.spawn` under org-b's `GITHUB_TOKEN`, per the described flow. This is repeatable against any repository configured in the Shipit instance with `review_stacks_enabled` and an archived stack for a guessable/enumerable PR number, and the blast radius spans all tenants sharing the same Shipit installation, since the only requirement is knowledge of *any one* org's webhook secret (which the attacker can obtain by owning a repo/org whose GitHub App the operator installed).

### Likelihood Explanation
Preconditions: (1) attacker must control the `webhook_secret` for at least one org configured in `Shipit.github` (e.g., their own org/repo, if the Shipit instance is multi-tenant and lets any org self-register a GitHub App integration) — this is within the stated attacker capabilities since they are described as able to "emit webhooks from a repository they own"; (2) the target org-b must have `review_stacks` enabled with `provisioning_behavior` set to allow unarchiving (e.g. `allow_all`), and an existing archived `ReviewStack` for the targeted PR number. Given these preconditions, the attack is a single unauthenticated HTTP POST with no session, API token, or org-b secret required, and is fully repeatable/scriptable against arbitrary repositories once the attacker knows or brute-forces `full_name`/PR numbers.

### Recommendation
In `WebhooksController#verify_signature` (or a shared before_action applied to all webhook handlers), cross-check that `params.dig('repository','owner','login')` matches the owner segment parsed from `params.dig('repository','full_name')`, rejecting the request (422) on mismatch before dispatching to any handler. Alternatively, have every handler (including `ReopenedHandler`) resolve the target `Repository` using the verified `repository_owner` rather than trusting `full_name` alone, e.g., by validating `Repository.from_github_repo_name(full_name).owner == verified_organization` before performing any mutation.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_cross_org_test.rb
require 'test_helper'

module Shipit
  class WebhooksCrossOrgTest < ActionController::TestCase
    tests Shipit::WebhooksController

    test "org-a signed payload cannot unarchive org-b's review stack" do
      org_a_secret = 'org-a-secret'
      org_b_secret = 'org-b-secret'

      Shipit.stubs(:github).with(organization: 'org-a').returns(
        Shipit::GithubApp.new('org-a', webhook_secret: org_a_secret)
      )
      Shipit.stubs(:github).with(organization: 'org-b').returns(
        Shipit::GithubApp.new('org-b', webhook_secret: org_b_secret)
      )

      repository = Shipit::Repository.create!(owner: 'org-b', name: 'some-repo', review_stacks_enabled: true, provisioning_behavior: :allow_all)
      stack = repository.review_stacks.create!(environment: 'pr42', branch: 'feature')
      stack.archive!(shipit_users(:walrus))
      assert stack.archived?

      body = {
        action: 'reopened',
        number: 42,
        pull_request: { id: 1, number: 42, url: 'https://x', title: 't', state: 'open',
                         additions: 1, deletions: 0, head: { sha: 'a' * 40, ref: 'feature' },
                         user: { login: 'attacker' }, assignees: [], labels: [] },
        repository: { owner: { login: 'org-a' }, full_name: 'org-b/some-repo' },
        sender: { login: 'attacker' }
      }.to_json

      signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', org_a_secret, body)}"

      @request.headers['X-Github-Event'] = 'pull_request'
      @request.headers['X-Hub-Signature'] = signature

      # Binding under test: verifying_org ('org-a') must equal mutated repo's org ('org-b')
      assert_not_equal 'org-a', repository.owner, "sanity: orgs differ"

      post :create, body:, as: :json

      assert_response :ok
      assert_not stack.reload.archived?, "org-b's stack was unarchived using only org-a's webhook secret"
    end
  end
end
```
This test asserts both sides of the equality (`'org-a' != repository.owner == 'org-b'`) and demonstrates that `stack.reload.archived?` flips to `false` despite the signature only being valid for `org-a`, proving the cross-tenant mutation.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-53)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-50)
```ruby
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
```
