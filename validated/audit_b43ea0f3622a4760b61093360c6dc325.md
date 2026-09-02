### Title
Webhook signature verification is bound to `repository.owner.login` while the repository acted upon is taken from the unverified `repository.full_name` field, allowing cross-repository/cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate an inbound webhook's HMAC signature against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')`. Once the signature is verified, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the **entire raw payload** to handlers such as `PushHandler`, which resolve the target `Stack` using a *different* field of the same payload: `payload.dig('repository', 'full_name')` (`Handler#repository_name`). These two fields are never cross-validated against each other.

### Finding Description
- Signature verification binding: `Shipit.github(organization: repository_owner)` in `app/controllers/shipit/webhooks_controller.rb` (lines 25-30), where `repository_owner` comes from `repository.owner.login` (or `organization.login`) — line 61. [1](#0-0) [2](#0-1) 

- Repository-resolution binding used by handlers: `Handler#repository_name` reads `payload.dig('repository', 'full_name')`, and `Handler#stacks` uses it to look up the target `Repository`/`Stack` via `Repository.from_github_repo_name`. [3](#0-2) 

- `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on the matching branch of that repository. [4](#0-3) 

Because `repository.owner.login` (used to pick the signing secret) and `repository.full_name` (used to pick the acted-upon repository/stack) are independent, attacker-controlled JSON fields inside the same webhook body, an attacker who legitimately controls (or has compromised) a GitHub App installation/webhook secret for **one** organization tracked by this Shipit instance can craft a payload where:
- `repository.owner.login = "org-a"` (their own org — signature computed with the Org A secret they know, so `verify_signature` passes), and
- `repository.full_name = "org-b/other-repo"` (a completely different, unrelated repository/organization tracked by the same Shipit instance).

This breaks the intended binding: `organization authenticated == repository written`. The signature only proves the request originated from a holder of Org A's webhook secret; it proves nothing about the `repository.full_name` value that handlers actually act on.

### Impact Explanation
This lets an attacker who legitimately controls one organization's GitHub App/webhook secret trigger handler side effects (e.g., forcing `GithubSyncJob`/`sync_github` calls, or with other events, mutating `Status`, `CheckRun`, `Membership`/`Team` records, or firing `pull_request`/`merge` handlers) scoped to a **different** organization's repository/stack that they have no legitimate access to. This is a cross-repository trust boundary violation: an org boundary meant to be enforced by the webhook signature is bypassed for the purposes of selecting which repository's data gets modified, satisfying the "cross-repository writes" high/critical impact category.

### Likelihood Explanation
Exploitability requires the attacker to already control a valid webhook secret for at least one organization configured on the shared Shipit instance (multi-tenant deployments configuring multiple GitHub Apps/organizations via `Shipit.github(organization: ...)` — evidenced by the `GithubOrganizationUnknown` rescue path keyed on `repository_owner`). This is a realistic scenario for any Shipit deployment serving more than one organization/team where each org's admins can see their own webhook secret but should not be able to affect other orgs' stacks. No repository write access or Shipit session is needed — only the ability to craft and sign an HTTP POST to `/webhooks` with a mismatched `repository.owner.login` / `repository.full_name`.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`/`Handler#stacks`), enforce that the organization/owner used to select and verify the signing secret is the **same** value used to resolve the target repository — e.g., validate that `Repository.from_github_repo_name(payload.dig('repository','full_name'))`'s owner matches `repository_owner` before dispatching to handlers, rejecting the webhook otherwise.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` and `org-b`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md`'s multi-org config pattern and `Shipit.github(organization:)`).
2. Attacker is a legitimate admin of `org-a`'s GitHub App and therefore knows `org-a`'s `webhook_secret`.
3. Attacker crafts a `push` webhook payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
4. Attacker signs the raw body with `org-a`'s webhook secret and sets `X-Hub-Signature` accordingly, then POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "org-a")` and successfully verifies the signature against `org-a`'s secret.
6. `PushHandler#stacks` resolves `Repository.from_github_repo_name("org-b/victim-repo")` and calls `sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `org-b`'s stack(s), even though the attacker has no relationship to `org-b`. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-38)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-23)
```ruby
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
