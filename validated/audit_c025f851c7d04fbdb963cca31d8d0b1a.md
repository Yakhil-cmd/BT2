### Title
Webhook signature is bound to `repository.owner.login`/`organization.login`, but every event handler acts on `repository.full_name` from the same unverified-for-consistency payload, allowing cross-organization forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the JSON body, and only proves that *some* configured organization's secret matches the signature. [1](#0-0) [2](#0-1)  Once the signature check passes, every registered handler resolves the target `Repository`/`Stack` using a completely different field of the same payload, `repository.full_name`, with no check that it belongs to the organization whose secret validated the request. [3](#0-2) 

### Finding Description
In a multi-organization Shipit deployment (explicitly a supported configuration, each org having its own `webhook_secret`), the binding the engine relies on is:

`organization whose webhook_secret authenticated the request == organization owning the repository being written to`

`verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` and fetches `Shipit.github(organization: repository_owner)` to verify the HMAC. [1](#0-0) [2](#0-1)  That only proves the attacker knows the webhook secret configured for the organization named in that field — it says nothing about the rest of the JSON body.

However, `Handler#stacks`/`#repository_name` (the base class used by `PushHandler`, `StatusHandler`, the `PullRequest::*` handlers, `MembershipHandler`, etc.) resolves the affected `Repository` using `payload.dig('repository', 'full_name')`, an independent key that is never cross-checked against `repository_owner`. [3](#0-2)  An attacker who is an admin of their own GitHub organization ("Org A") legitimately possesses/configures Org A's `webhook_secret` (it is set by whoever creates the GitHub App for that org, per `docs/setup.md`). [4](#0-3)  With that secret they can:
1. Set `organization.login` (or `repository.owner.login`) = `"org-a"` so `verify_signature` fetches Org A's `github_app` and the HMAC computed with Org A's secret validates.
2. Set `repository.full_name` = `"org-b/some-repo"` — a repository belonging to a different organization/customer hosted on the same Shipit instance.

Because the signature check and the repository-resolution logic use disjoint fields, the forged event is accepted and dispatched to handlers operating on Org B's stack.

### Impact Explanation
This breaks the deployment-trust binding "organization that authenticated versus the repository that is written," enabling cross-repository/cross-organization writes with only a low-privilege credential (one's own webhook secret):
- A forged `status` event (`StatusHandler`) can create arbitrary commit statuses (`state: success`) for any SHA in another org's repository, which can satisfy `ci.require`/`merge.require` checks and enable an unauthorized deploy or auto-merge on that stack. [5](#0-4) 
- A forged `push` event (`PushHandler`) forces `GithubSyncJob`/`sync_github` on another org's stack. [6](#0-5) 
- Forged `pull_request` events can archive/unarchive stacks or otherwise mutate PR/merge-queue state belonging to a different organization's repository. [7](#0-6) 

This satisfies the "cross-repository writes" / "unauthorized deploy … or merge" impact bar without requiring a Shipit session, `ApiClient` token, or `GITHUB_TOKEN`.

### Likelihood Explanation
Requires the engine to be configured for multiple GitHub organizations sharing one Shipit instance — a configuration explicitly documented and supported (`config/secrets.development.example.yml` shows the multi-org schema with per-org `webhook_secret`). [8](#0-7)  Any organization admin who is entitled to install/configure their own GitHub App (and thus knows their own org's webhook secret) can mount this attack against any other tenant org on the same instance, without any access to that other org.

### Recommendation
In `Handler#repository_name`/`#stacks`, verify that the resolved repository's owner matches the `repository_owner`/`organization.login` that was used to select and validate the webhook signature (or pass the verified organization down to handlers and enforce equality), rejecting the event otherwise.

### Proof of Concept
1. Attacker is an admin of `org-a` and knows `org-a`'s `webhook_secret` (set when creating/configuring the GitHub App per `docs/setup.md`).
2. Attacker crafts a JSON body for the `status` event:
```json
{
  "sha": "<victim-sha-in-org-b-repo>",
  "state": "success",
  "context": "ci/required",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(org-a-secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches `Shipit.github(organization: "org-a")`, and the signature matches — request is accepted. [1](#0-0) 
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — commits belonging to `org-b/victim-repo` (resolved independently via `repository.full_name` in other handlers/lookups) — and creates a passing status, potentially unblocking a deploy/merge on `org-b`'s stack despite the attacker having no relationship to `org-b`. [9](#0-8)

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

**File:** docs/setup.md (L20-30)
```markdown
## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L41-57)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
