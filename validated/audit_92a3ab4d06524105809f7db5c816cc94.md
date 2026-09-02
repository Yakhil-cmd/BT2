This confirms the binding break: `WebhooksController#verify_signature` selects the webhook secret using the **claimed** `repository.owner.login` (or `organization.login`) from the unverified JSON body, while every `Handler` subsequently resolves the target `Stack` using the **claimed** `repository.full_name` from that same unverified body [1](#0-0) [2](#0-1) . Neither the signature nor any handler enforces that the organization used to select/verify the HMAC secret actually matches the owner segment of `repository.full_name` that is acted upon.

### Title
Webhook signature is verified against the organization named in the unverified payload, not the repository actually acted upon - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit deployment (`config/secrets.yml` supports per-organization `github:` blocks with independent `webhook_secret` values, as documented in `docs/setup.md`), `WebhooksController#verify_signature` picks which organization's secret to check against using `repository_owner`, itself read straight out of the unverified request body [3](#0-2) . Once the HMAC check passes for *that* organization's secret, the raw, attacker-controlled `params` hash is dispatched unmodified to every registered `Handler`, which independently derives the target repository via `payload.dig('repository', 'full_name')` [4](#0-3) .

### Finding Description
The binding that should hold is:
`organization authenticated by verify_signature (repository.owner.login) == organization of repository.full_name acted on by the Handler`

Before the fix this equality is never checked. `verify_signature` only proves "the sender knows organization X's webhook secret"; it says nothing about which repository the payload subsequently claims to modify. A holder of organization X's `webhook_secret` (e.g., anyone administering a GitHub App installed on their own org X inside a Shipit instance that is also configured to serve org Y) can post a JSON body where `repository.owner.login`/`organization.login` = `X` (so the HMAC matches and `verify_signature` passes) but `repository.full_name` = `"Y/some-repo"` — an org/repo actually served by that same Shipit instance under a different `webhook_secret`. `Handler#stacks` resolves the stack purely from `repository.full_name`, with no re-check against the organization that authenticated the request [2](#0-1) .

This is directly analogous to the oracle report's root cause: the trust anchor (chainlink address / here, the webhook secret keyed by org) is fixed/selected once from a field, but the value later acted upon (price / here, `repository.full_name`) is never checked to still correspond to that same anchor.

### Impact Explanation
The `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack matching the forged repository's branch [5](#0-4) , and `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`, and the `pull_request/*` handlers similarly trust `repository.full_name`/team fields from the same unverified payload to mutate `Commit` statuses, enqueue sync/merge jobs, or create `Team`/`User` records tied to repositories/organizations that were never actually authenticated by the signature. In a multi-org Shipit install this allows a party who controls one organization's app/webhook secret to inject forged push/status/merge events against a **different** organization's tracked repositories — a cross-organization write that can trigger unintended sync, merge-queue mutation, or deploy triggers for repositories they do not own.

### Likelihood Explanation
Requires (a) a Shipit instance configured to serve more than one GitHub organization (the documented multi-org `secrets.yml` shape), and (b) the attacker legitimately possessing a `webhook_secret` for at least one of those organizations (e.g., because they administer the GitHub App installed on their own org, which is installed on the same shared Shipit instance). This is a realistic configuration for shared/hosted Shipit deployments serving multiple teams/orgs, and requires no privileged Shipit account, API token, or repository write access — only knowledge of one org's webhook secret and the ability to POST to the public `/webhooks` endpoint.

### Recommendation
After computing `event`/`params` and successfully verifying the signature, re-validate that the organization implied by `repository.full_name` (or `organization.login`) matches the `repository_owner` used to select the verifying `github_app`/secret before dispatching to handlers, rejecting (422) any mismatch.

### Proof of Concept
1. Configure Shipit with two organizations, `orgX` (attacker-controlled GitHub App, webhook secret known to attacker) and `orgY` (victim org, tracked stacks e.g. `orgY/victim-repo`), both served by the same Shipit instance.
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "full_name": "orgY/victim-repo", "owner": { "login": "orgX" } }
}
```
3. Attacker signs the raw body with `orgX`'s known `webhook_secret` and sets `X-Hub-Signature` accordingly, POSTs to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "orgX")` and verifies the signature successfully [1](#0-0) .
5. `PushHandler` (via `Handler#stacks`) resolves stacks from `repository.full_name` = `orgY/victim-repo` and calls `sync_github` on it, even though the signature only proved control of `orgX`'s secret [2](#0-1) [5](#0-4) .

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
