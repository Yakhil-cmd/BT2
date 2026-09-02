### Title
Webhook signature verified against a different GitHub organization than the repository the event is applied to, allowing cross-tenant status/push spoofing - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to verify the HMAC signature against using a field taken straight from the **unverified** JSON body (`repository.owner.login` or `organization.login`). Once the signature check passes, every downstream `Webhooks::Handlers::Handler` resolves the target `Stack` using a **different** field of the same unverified body — `repository.full_name` — via `Repository.from_github_repo_name`. Nothing ties the organization whose secret validated the signature to the repository/organization that the event actually mutates.

### Finding Description
The controller computes the verification target from attacker-influenced JSON before the HMAC is checked: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the `GithubApp`/secret configured for that org (Shipit supports multiple orgs, each with its own `webhook_secret`, as shown in the multi-app fixture): [3](#0-2) 

`verify_webhook_signature` then just HMAC-compares against that org's secret: [4](#0-3) 

Once verification succeeds, the actual event target is resolved from a **separate, still-unverified** field of the same payload: [5](#0-4) 

Nothing in this chain enforces `repository.full_name`'s owner == the org identified by `repository.owner.login`/`organization.login` used to pick the secret. An attacker who knows/controls the `webhook_secret` for *any one* org configured on the Shipit instance (e.g. their own org's GitHub App, which they legitimately administer) can:
1. Set `repository.owner.login` (or `organization.login`) to their own org, so `verify_signature` selects and validates against their own known secret.
2. Set `repository.full_name` to an arbitrary other tracked repository (e.g. `OrgB/victim-repo`), which is what `Handler#stacks` actually uses to select the `Stack`.

This breaks the intended equality `org that signed == org whose repo is mutated`, exactly analogous to the reported bug class where a stale/wrong authority is used to gate an action that is actually performed against a different resource.

Concrete exploitable handler: `StatusHandler` (event `status`) creates a `Status` on the target commit directly from attacker-supplied `state`/`context`, as shown by the existing test: [6](#0-5) 

That status feeds `Commit#deployable?`, which is the CI gate that authorizes deploys: [7](#0-6) 

So a forged, cross-tenant `status` webhook lets an attacker mark a commit on a target repository/stack as `success`, satisfying `deployable?` and bypassing the CI-required-status gate for that stack's deploys — even though the signature only proved control of a *different* organization's secret. `PushHandler`/`CheckSuiteHandler` are similarly reachable and can force syncs/refreshes on stacks that don't belong to the attacker's org: [8](#0-7) 

### Impact Explanation
This crosses a repository/authentication boundary explicitly in scope: the organization that authenticated (via HMAC secret) is not the repository that is written. The most severe consequence is bypassing the CI/status gate that authorizes deploys (`Commit#deployable?`), enabling an **unauthorized deploy** on a stack the attacker does not administer — matching the Critical impact bar ("unauthorized deploy"). Lesser but still relevant effects include forcing `GithubSyncJob`/`CacheDeploySpecJob` runs and injecting/removing team memberships (`membership` event) for organizations the attacker does not control, since none of these handlers re-validate the signing org against the acted-upon repository/org.

### Likelihood Explanation
Requires only that Shipit is configured for more than one GitHub organization (a documented, supported configuration) and that the attacker legitimately possesses one org's `webhook_secret` (e.g. they administer their own GitHub App integrated with the same Shipit instance) while targeting a repository/stack belonging to another configured organization whose full name is typically public knowledge. No `ApiClient` token, session, or GitHub App private key for the *victim* org is needed — only the attacker's own, legitimately-issued secret for their own org. This is a plausible, low-effort attack path once multi-org hosting is in use.

### Recommendation
After signature verification succeeds, re-derive `repository_owner`/`organization` strictly from the same trust context used to pick the verifying secret, and reject the event (or re-verify) if `repository.full_name`'s owner does not match the org that was used to select the `webhook_secret`. Concretely, in `WebhooksController#verify_signature`/`create`, assert that `params.dig('repository','owner','login')` (or `organization.login`) equals the owner segment of `params.dig('repository','full_name')` before dispatching to handlers, and have `Handler#stacks` scope by that already-verified owner rather than trusting `repository.full_name` alone.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` (attacker-administered GitHub App, secret known to attacker) and `OrgB` (victim, tracks stack `OrgB/victim-repo`), per the supported multi-org config shown in `secrets_double_github_app.yml`.
2. Attacker crafts a `status` webhook body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required",
  "repository": { "full_name": "OrgB/victim-repo", "owner": { "login": "OrgA" } }
}
```
3. Attacker computes `X-Hub-Signature` using `OrgA`'s known `webhook_secret` over the raw body and sends it to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` reads `repository_owner` = `"OrgA"` from the body, fetches `OrgA`'s `github_app`, and the signature validates successfully.
5. `Webhooks::Handlers::StatusHandler` (dispatched with the full, unverified payload) resolves `repository_name` = `"OrgB/victim-repo"` and creates a `success` `Status` on that commit in `OrgB`'s stack, as demonstrated by the existing `":state create a Status for the specific commit"` test pattern.
6. If that status satisfies the stack's required CI contexts, `Commit#deployable?` now returns true for a commit the attacker never had legitimate authority over, permitting an unauthorized deploy trigger.

### Citations

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
