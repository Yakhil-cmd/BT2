### Title
Webhook signature verified against `repository.owner.login`, but event processing acts on the repository named by `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's HMAC secret to check the GitHub webhook signature against using `repository.owner.login` (falling back to `organization.login`), but every event `Handler` subsequently resolves the repository/stack to act on using an entirely different payload field, `repository.full_name`. These two fields are never checked for consistency, so a payload can be crafted so the signature is verified against one organization while the mutations happen against a repository belonging to a different organization/stack.

### Finding Description
`WebhooksController#verify_signature` picks the app/secret to verify against like this: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (or `organization.login`) and is used solely to look up which organization's `webhook_secret` (via `Shipit.github(organization: repository_owner)`) validates `X-Hub-Signature`.

Once the signature check passes, `create` dispatches the whole raw JSON `params` to the matching handlers: [3](#0-2) 

Every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, the `PullRequest::*` handlers, etc.) inherits `Handler#stacks`/`#repository_name`, which resolves the target repository from a **different** field: [4](#0-3) 

So the binding that should hold is:
`organization authenticated by signature (repository.owner.login) == organization/repository whose stacks are mutated (repository.full_name)`

Nothing in the code enforces that `repository.full_name`'s owner segment matches `repository.owner.login`/`organization.login`. An attacker who legitimately controls a GitHub organization onboarded into this Shipit instance (and therefore knows/can produce a valid signature using their own org's `webhook_secret`) can send a webhook whose `X-Hub-Signature` is computed with their own secret, with `repository.owner.login` (or `organization.login`) set to their own org so verification passes, while `repository.full_name` is set to `"victim-org/victim-repo"`. `PushHandler#process` (or `StatusHandler`, `CheckSuiteHandler`, pull-request handlers) then resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and acts on that stack — e.g. triggering `stack.sync_github(expected_head_sha:)`, creating commit statuses via `Commit#create_status_from_github!`, or creating/archiving `ReviewStack`s — none of which belong to the authenticating organization.

This mirrors the reported bug class exactly: two structurally distinct fields (`real_output` vs `real_output_in_tx_index`; here `repository.owner.login` vs `repository.full_name`) are conflated by one code path assuming they always agree, and only one of them is actually checked/authenticated while the other is what gets acted upon.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust boundary explicitly called out as in-scope. It lets an operator of any onboarded GitHub organization forge signed-looking webhook events (push/status/check_suite/pull_request/membership) that mutate stacks belonging to unrelated repositories/organizations hosted on the same Shipit instance — e.g. forcing `GithubSyncJob`/`sync_github` calls, injecting fabricated commit statuses that can unblock/allow deploys (`StatusHandler` → `Commit#create_status_from_github!`), or creating/archiving review stacks for a victim repository. This is a cross-repository, cross-organization write achieved purely by crafting the JSON body, without needing the victim organization's webhook secret.

### Likelihood Explanation
Requires the attacker to control (or have signing capability for) at least one organization already configured in this Shipit instance — a realistic scenario for any Shipit deployment serving multiple organizations/tenants, since webhook secrets are configured per-organization and the attacker only needs their own. No repository write access, session, or API token is needed; only the ability to send an HTTP POST with a validly-signed-for-their-own-org body to the public webhooks endpoint.

### Recommendation
Derive the organization used for signature verification from the same field used for repository resolution (`repository.full_name`'s owner segment), or, conversely, have `Handler#repository_name`/`#stacks` cross-check that the resolved repository's owner matches the organization whose secret validated the signature. Reject the payload if the two disagree.

### Proof of Concept
1. Attacker's own GitHub organization `attacker-org` is configured in this Shipit instance with `webhook_secret = S`.
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S, body)>` using their own known secret `S`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and the signature verifies successfully. [5](#0-4) 
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` (from `repository.full_name`) and calls `stack.sync_github(expected_head_sha: params.after)` on a stack the attacker does not own. [6](#0-5) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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
