### Title
Webhook signature verified against attacker-controlled organization while handlers act on an independent, unvalidated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-GitHub-App deployments, `WebhooksController#verify_signature` selects the webhook secret to validate a request against based on `repository.owner.login` (or `organization.login`) pulled straight from the untrusted JSON body, while the handlers that actually act on the payload (e.g. `PushHandler`) resolve the target `Repository`/`Stack` using the independent `repository.full_name` field. Because these two fields are never cross-checked, an attacker who controls (or is a member of) any organization configured in Shipit's multi-org `github` secrets — and therefore legitimately knows that organization's webhook secret — can forge a signature that is valid for their own org while pointing `repository.full_name` at a stack belonging to a completely different, more trusted organization tracked by the same Shipit instance.

### Finding Description
`verify_signature` computes the organization used to pick the `GitHubApp` (and thus the secret) purely from the request body: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

This `repository_owner` is used only to select `Shipit.github(organization: repository_owner)` for signature verification; when Shipit is configured for multiple GitHub organizations, each organization has its own `webhook_secret`, and `Shipit.github` looks the secret up strictly by this attacker-supplied field. [3](#0-2) 

After signature verification succeeds, `WebhooksController#create` dispatches the same raw, attacker-controlled JSON body to the registered handler for the event: [4](#0-3) 

Handlers such as `PushHandler` determine which Shipit `Repository`/`Stack` to act on using a completely different JSON field — `repository.full_name` — with no re-validation against `repository.owner.login`: [5](#0-4) [6](#0-5) 

Because `repository.owner.login` (used to select the signing secret) and `repository.full_name` (used to select the acted-upon repository/stack) are independent, attacker-controlled fields in the same JSON body, nothing enforces `repository.full_name.start_with?(repository.owner.login)`. An attacker who is an admin of, or otherwise knows the webhook secret for, any GitHub organization configured in Shipit's `github:` multi-org secrets (a legitimate, unprivileged capability from Shipit's point of view — they only need to run their own GitHub App/organization, not have any access to Shipit itself or to the victim's GitHub org) can:

1. Craft a webhook body with `repository.owner.login` = their own organization (so `Shipit.github(organization: repository_owner)` resolves to *their* `GitHubApp` and secret).
2. Sign the payload with that org's known webhook secret, producing a fully valid `X-Hub-Signature`.
3. Set `repository.full_name` to `victim-org/victim-repo` — a Repository tracked by Shipit under a different, unrelated organization.
4. Send this to `/webhooks`. `verify_signature` succeeds (correct secret for the claimed `repository_owner`), and the dispatched handler (`PushHandler`, `StatusHandler`, etc.) resolves and mutates state for the victim's stack via `Handler#repository_name` / `Handler#stacks`.

This breaks the binding: `organization that authenticated == repository that is written`. The equality that should hold is `repository.owner.login == owning organization of repository.full_name`, but the code never asserts it — verification and effect operate on two unrelated fields of the same untrusted body.

### Impact Explanation
Depending on which webhook event/handler is abused, the practical effect ranges from triggering unauthorized `GithubSyncJob` runs (`PushHandler`) that resync commits/statuses for a victim stack, to forging commit statuses via the `status` event handler for a victim's commit. If any tracked stack relies on CI status webhooks to gate deploys or on the merge queue to auto-merge once required statuses are green, an attacker who only needs to control one configured-but-unrelated GitHub organization can inject state (fake green CI, fake pushes) into a victim repository's Shipit-tracked stack — a cross-repository/cross-organization write achieved without any credential belonging to the victim organization, satisfying the "cross-repository writes" / "unauthorized deploy" criteria.

### Likelihood Explanation
Exploitability requires a Shipit deployment configured with more than one GitHub organization in `github:` secrets (a documented, supported configuration — "Using Multiple Github Applications"), and requires the attacker to control one of those configured organizations' webhook secret (something they legitimately have if they administer their own org's installed GitHub App). No access to Shipit itself, no GitHub access to the victim org, and no privileged Shipit account is required — only the ability to send an HTTP POST to the public `/webhooks` endpoint with a self-signed body. This is a realistic multi-tenant misconfiguration risk wherever Shipit hosts stacks for multiple organizations.

### Recommendation
After signature verification, re-validate that `repository.full_name` (or `organization.login` for org-scoped events) is actually owned by the same organization used to select the signing secret, e.g. reject the webhook if `repository.owner.login` (or the org that owns `full_name`) does not match `repository_owner` used in `verify_signature`, or better, resolve the target `Repository`/`Stack` using the same trusted `repository_owner` value that gated signature verification rather than trusting a second, independent field in `Handler#repository_name`.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` (attacker administers) and `victim-org` (hosts a tracked stack, e.g. `victim-org/victim-repo`), each with its own `webhook_secret` per the multi-org config in `config/secrets.yml`.
2. Craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker chosen sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Sign this exact raw body with `attacker-org`'s known `webhook_secret` (HMAC-SHA1) and set it as `X-Hub-Signature: sha1=<signature>`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and successfully verifies the signature against the attacker's own secret.
6. `PushHandler#process` (via `Handler#repository_name` reading `payload.dig('repository','full_name')`) resolves the actual `victim-org/victim-repo` stack and calls `stack.sync_github(expected_head_sha: ...)`, mutating state for a repository the attacker's organization has no relationship to.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
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

**File:** lib/shipit.rb (L61-63)
```ruby

  GithubOrganizationUnknown = Class.new(StandardError)
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
