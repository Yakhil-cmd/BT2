### Title
Webhook signature verification is keyed on `repository.owner.login` while event processing acts on `repository.full_name`, allowing cross-organization webhook forgery in multi-app Shipit deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
Shipit supports hosting multiple GitHub Apps in a single deployment, one per GitHub organization, each with its own `webhook_secret` [1](#0-0) , as reflected in the test fixture `test/dummy/config/secrets_double_github_app.yml`. The `WebhooksController#verify_signature` action selects *which* organization's app/secret to validate the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`) [2](#0-1) [3](#0-2) . However, the event handlers that actually act on the payload (e.g. `PushHandler`) resolve the target `Repository`/`Stack` using a **different** field: `payload.dig('repository', 'full_name')` [4](#0-3) , which is parsed independently by `Repository.from_github_repo_name` into owner/name [5](#0-4) .

### Finding Description
The equality that should hold is: **organization whose secret authenticated the webhook == organization of the repository the handler actually writes to**.

Before the attack: for a legitimate GitHub-delivered webhook, `repository.owner.login` and the owner portion of `repository.full_name` always match, because both are populated by GitHub from the same repository object.

After the attack: because `/webhooks` is a public, unauthenticated endpoint (no session or API token required — `skip_before_action :verify_authenticity_token` and no `Authentication` concern is included) [6](#0-5) , an attacker who legitimately owns/administers **one** GitHub organization/App configured on the same Shipit instance (Org A, and thus knows Org A's `webhook_secret`) can hand-craft a POST body where:
- `repository.owner.login` = `"org-a"` (used only to select which secret verifies the HMAC)
- `repository.full_name` = `"victim-org/victim-repo"` (used to look up the actual `Repository`/`Stack` to act on)

`verify_signature` computes `Shipit.github(organization: "org-a")` and validates the HMAC using Org A's secret [2](#0-1)  — which succeeds because the attacker signed the body with their own known secret. `Shipit::Webhooks.for_event(event)` is then dispatched with the raw JSON [7](#0-6) , and e.g. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name(repository_name)` where `repository_name` comes from `full_name`, not `owner.login` [8](#0-7) [4](#0-3) . This lets a signature validated under Org A's credentials drive actions against a Stack belonging to an unrelated Org B/victim repository.

### Impact Explanation
For `push` events this reaches `stack.sync_github(expected_head_sha: params.after)` on the victim's stack, which is queued as `GithubSyncJob` with an attacker-chosen `after` SHA and ref, letting an attacker who controls a second onboarded organization influence sync/deploy state of a completely unrelated organization's stack that they have no legitimate access to — i.e., cross-organization/cross-repository interference achieved without ever knowing the victim organization's own `webhook_secret`. This satisfies the "cross-repository writes" / "unauthorized deploy" impact class, analogous to the Tapioca report's cross-user impersonation via an unverified sender binding.

### Likelihood Explanation
Requires the deployment to be configured with `Shipit.github` multi-organization support (documented, first-class feature) and the attacker to control at least one of the onboarded organizations/Apps (its own legitimate `webhook_secret`). Given that, the exploit is a single unauthenticated HTTP POST to the public `/webhooks` endpoint with a crafted JSON body and matching HMAC — no session, no `ApiClient` token, no privileged account needed to reach the victim's data.

### Recommendation
`verify_signature` and the handlers must derive the organization/repository binding from the *same* field. Either verify the HMAC using the owner parsed out of `repository.full_name` (matching what the handlers use), or have handlers cross-check that `repository.owner.login` equals the owner segment of `repository.full_name` and reject on mismatch before dispatching to `Shipit::Webhooks.for_event`.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` (attacker-controlled) and `victim-org` (has a tracked `Stack` for `victim-org/victim-repo`), per the multi-app pattern in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker crafts JSON:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": {"login": "org-a"},
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(org-a webhook_secret, body)>`.
4. POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: "org-a")` and passes verification [2](#0-1) .
6. `PushHandler` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `GithubSyncJob` for the victim's `Stack` with attacker-supplied `expected_head_sha` [9](#0-8) , despite the attacker never possessing `victim-org`'s webhook secret.

### Citations

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/controllers/shipit/webhooks_controller.rb (L1-16)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
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
```
