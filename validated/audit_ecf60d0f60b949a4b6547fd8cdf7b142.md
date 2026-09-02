### Title
Webhook signature is verified against a secret selected by the attacker-controlled `repository.owner.login`/`organization.login` field, while every event handler resolves its target stack from the equally attacker-controlled `repository.full_name` field, with no cross-check between the two — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` picks *which* GitHub App/organization's `webhook_secret` to HMAC-verify the request against by reading `repository_owner`, which is taken straight from the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`), not from any authenticated GitHub-side context: [1](#0-0) [2](#0-1) 

Once the signature check passes for *that* organization's secret, `create` dispatches to per-event `Handler`s, all of which locate the affected `Repository`/`Stack` using a **different** field of the same body — `repository.full_name` — with no requirement that its owner match `repository_owner`: [3](#0-2) [4](#0-3) [5](#0-4) 

Shipit is explicitly multi-tenant at the GitHub-App/organization level — `Shipit.github(organization:)` looks up a distinct `webhook_secret`/`private_key` per organization, as configured e.g. in `config/secrets.development.shopify.yml` (`somegithuborg`, `someothergithuborg`, each with its own `webhook_secret`): [6](#0-5) 

### Finding Description
The equality that should hold is:

`organization whose webhook_secret authenticated the signature == organization that owns the repository the handler actually writes to`

Before the fix: `verify_signature` trusts `repository_owner` from the raw body to select the secret, and separately every `Handler` (Push, Status, Membership, PullRequest/*, etc.) trusts `repository.full_name` from the same body to select the target `Stack`/`Repository`/`Commit`. Nothing ties these two attacker-supplied fields together. Any party who legitimately controls one organization's GitHub App on a shared/multi-tenant Shipit instance (and therefore knows that organization's `webhook_secret`, since GitHub App creators configure it themselves) can POST directly to `/webhooks` with:
- `X-Github-Event` set to `push`/`status`/etc.
- `X-Hub-Signature` computed with **their own** org's `webhook_secret`
- a JSON body where `repository.owner.login`/`organization.login` == their own org (so `verify_signature` picks and validates against their own secret), but `repository.full_name` == `<victim-org>/<victim-repo>`.

`verify_signature` passes (the signature is valid for the secret it looked up), and the handler then acts on the victim repository/stack that belongs to a completely different, unrelated organization.

After the fix (needed): the organization used to pick the verification secret must be the same organization whose repository the handler is permitted to act on — e.g., enforce that `repository.full_name`'s owner equals `repository_owner`, or resolve the target `Stack` first and verify the signature using that `Stack`'s own organization's secret instead of a value drawn from the unauthenticated body.

### Impact Explanation
The most damaging instance is `StatusHandler`, which creates a `Commit::Status` for any commit `sha` present in the datastore across the *entire* Shipit instance, independent of the org used for verification: [7](#0-6) . Commit statuses are used to gate the merge queue and deploy readiness (`MergeRequest#all_status_checks_passed?`, required/blocking statuses in `deploy_spec`), so an attacker who owns any onboarded organization can forge a passing status for a required CI context on a victim organization's private repository/commit, helping bypass the CI gate that blocks a merge or an "unauthorized deploy". `PushHandler` similarly lets the attacker trigger a `GithubSyncJob`/resync on an arbitrary victim `Stack` (`stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }`), which can prematurely resume continuous delivery/deploys on a stack the attacker has no authorization over. This crosses the "escalation into authorization"/"unauthorized deploy" impact bar without needing any Shipit session, `ApiClient` token, or repository write access — only knowledge of one tenant's own `webhook_secret`, which the rules explicitly do not exclude (it's not the victim's secret, TLS interception, or a privileged account).

### Likelihood Explanation
Requires the attacker to be an onboarded organization/tenant on a shared Shipit instance (i.e., they legitimately know their *own* org's `webhook_secret`, as is normal for whoever set up the GitHub App) and to send a single crafted HTTP request. No social engineering, TLS interception, or victim credentials are needed — only that another org's repository/stack also exists on the same Shipit deployment. On single-tenant Shipit installs (one org only) this has no practical effect since there is nothing to cross into, but the code contains no boundary enforcing that, so any multi-org deployment is exposed.

### Recommendation
Do not let the request body decide which secret validates itself. Either:
1. Resolve the target `Stack`/`Repository` from `repository.full_name` first, then verify the signature using that repository's own organization's `webhook_secret` (instead of `repository_owner`); or
2. After both values are known, assert `repository.full_name`'s owner login equals `repository_owner`/`organization.login` before dispatching to any handler, rejecting mismatches with `422`.

### Proof of Concept
1. Shipit is configured with two tenants, `orgA` (attacker-controlled, webhook_secret known to the attacker) and `orgB` (victim), each with a `Stack` for their respective repos.
2. Attacker computes `X-Hub-Signature` over a crafted JSON body using `orgA`'s `webhook_secret`:
```json
{
  "ref": "refs/heads/main",
  "after": "<victim-relevant-sha>",
  "repository": { "full_name": "orgB/victim-repo", "owner": { "login": "orgA" } }
}
```
3. POST this body with header `X-Github-Event: push` to `/webhooks`.
4. `WebhooksController#verify_signature` computes `repository_owner = "orgA"`, fetches `Shipit.github(organization: "orgA")`, and the signature verifies successfully (it was HMAC'd with `orgA`'s real secret).
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("orgB/victim-repo")`, matching the victim's `Stack`, and triggers `stack.sync_github(expected_head_sha: ...)` on it — an action the attacker was never authorized to perform on `orgB`'s stack.
6. The same technique with `X-Github-Event: status` and a known commit `sha` from `orgB`'s repo lets the attacker inject arbitrary passing/failing commit statuses via `StatusHandler#process`, affecting `orgB`'s merge/deploy gating. [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-23)
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** test/controllers/webhooks_controller_test.rb (L109-127)
```ruby
    test "unknown github organization logs and returns unprocessable entity" do
      @request.headers['X-Github-Event'] = 'push'

      payload = JSON.parse(payload(:push_master))
      payload["repository"]["owner"]["login"] = "unknown-org"

      Shipit.stubs(:github).raises(Shipit::GithubOrganizationUnknown.new("unknown-org"))
      Rails.logger.expects(:warn).with([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=push",
        "repository_owner=unknown-org",
        "unknown_organization=unknown-org",
        "status=422"
      ].join(' '))

      post :create, body: payload.to_json, as: :json
      assert_response :unprocessable_entity
    end
```
