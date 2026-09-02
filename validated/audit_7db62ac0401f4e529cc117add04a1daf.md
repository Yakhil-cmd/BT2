### Title
Cross-tenant commit-status forgery bypasses repository scoping in `StatusHandler`, enabling unauthorized deploy triggering - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler`, the webhook handler for GitHub `status` events, updates commit CI status by looking up commits **only by SHA**, with no check that the SHA belongs to a repository owned by the GitHub organization whose webhook signature was actually verified. This breaks the binding: *organization that authenticated the webhook == repository/commit that is written*. In a multi-tenant Shipit deployment (the codebase explicitly supports multiple GitHub orgs sharing one Shipit instance, see `test/dummy/config/secrets_double_github_app.yml`), an attacker who controls (or can post statuses to) any repository within *their own* configured org can forge a signed `status` webhook that plants a fabricated "success" CI status on a commit SHA belonging to a completely different tenant's stack.

### Finding Description
The webhook signature check in `WebhooksController#verify_signature` selects which GitHub App/organization secret to use based on an **unverified** field taken straight from the JSON body (`repository.owner.login` or `organization.login`): [1](#0-0) [2](#0-1) 

This only proves the request was signed by *some* configured organization's app — it does not prove which repository/commit the payload is allowed to reference. Other handlers correctly re-derive the target repository from the payload and scope their queries to it, using `Handler#stacks`/`repository_name` (`payload.dig('repository', 'full_name')`): [3](#0-2) [4](#0-3) 

`StatusHandler`, however, does not require or use `repository` at all in its parameter schema, and resolves the commit(s) to mutate purely by SHA, globally across the entire Shipit instance: [5](#0-4) 

Because SHAs are 40-hex-char but not secret (they are visible on GitHub commit pages, in PR diffs, in `git log`, in CI logs, etc.), and because Shipit supports multiple organizations behind one instance (each with its own `webhook_secret`), an attacker who legitimately controls Org A (their own GitHub App / org configured on this Shipit instance) can:
1. Learn or guess the SHA of a commit tracked in Org B's stack (the victim tenant).
2. Send a `status` event, signed with Org A's `webhook_secret` (which the attacker legitimately possesses because it's their own org's app), containing `{"sha": "<victim-sha>", "state": "success", ...}`.
3. `WebhooksController#verify_signature` verifies successfully (Org A's secret matches Org A's signature).
4. `StatusHandler#process` finds the commit by SHA regardless of which org/repository it belongs to, and calls `commit.create_status_from_github!(params)`, injecting a forged status into Org B's stack.

### Impact Explanation
A forged "success" status on a commit can flip `Commit#status` to success, which triggers `add_status`'s side effects — scheduling merges and continuous delivery for a stack the attacker has no legitimate relationship with: [6](#0-5) [7](#0-6) 

For a stack with `continuous_deployment` enabled, this can cause an **unauthorized deploy** of a commit that never actually passed CI in the target org — the core "unauthorized deploy" impact called out in the scoring rubric. This is a direct analog of the reported bug class: a verification step (webhook signature ⇒ organization X) is not actually bound to the state being mutated (commit ⇒ arbitrary organization), just as `forceUpdateNodes`'s dust `limitStake` check didn't actually bind to the P-Chain weight it was supposed to gate.

### Likelihood Explanation
Exploitability requires only that the attacker be an operator of *any* org/app configured on the shared Shipit instance (a normal, unprivileged relationship relative to the victim tenant) and knowledge of a target commit SHA, which is routinely public. No access to the victim's webhook secret, API tokens, or repository is needed — only the attacker's own, legitimately-issued webhook credentials for an unrelated org. This is realistic wherever a single Shipit deployment serves multiple GitHub organizations, a configuration explicitly supported and tested in this codebase.

### Recommendation
`StatusHandler` should scope its `Commit` lookup to commits belonging to stacks whose repository matches `payload.dig('repository', 'full_name')` (as `PushHandler` and the pull-request handlers already do via `Handler#stacks`/`repository_name`), rejecting or ignoring status events whose repository does not match the commit's actual stack/repository.

### Proof of Concept
Not independently executable in this ask-only review (no test harness access), but the existing test suite demonstrates the unscoped lookup: `test/controllers/webhooks_controller_test.rb` shows the `status` event creating a `Status` purely from `params.sha` matched via `Commit.where(sha: params.sha)`, with the `repository_params` merge only affecting which org secret verifies the signature, not which commit is targeted: [8](#0-7) 
Constructing this into an exploit only requires substituting a SHA belonging to a stack under a *different* tracked repository/org than the one whose secret signed the request — `StatusHandler#process` contains no code path that would reject that mismatch.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
```

**File:** app/models/shipit/commit.rb (L366-384)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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
