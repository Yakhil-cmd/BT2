### Title
Cross-organization webhook forgery due to unverified `repository.full_name` binding - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
When a Shipit installation is configured with multiple GitHub Apps (one per organization, as documented), the webhook controller selects which organization's `webhook_secret` to verify the HMAC signature against using the payload's `repository.owner.login` field, but the event handlers act on a stack/repository selected from the completely separate, unauthenticated-relative-to-that-choice `repository.full_name` field. An attacker who administers *any* one of the configured GitHub organizations (and therefore knows/controls that organization's own `webhook_secret`) can forge a signed webhook whose `repository.owner.login` matches their own org (so the signature check for that org's secret passes) while `repository.full_name` names a repository belonging to a *different* configured organization, causing Shipit to act on that victim organization's stack.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to check against from `repository_owner`, derived from the request body itself: [1](#0-0) [2](#0-1) 

The signature is a valid HMAC over the *whole* raw body, so it does prove the sender knows the secret associated with `repository_owner`. But nothing ties that verified organization to the repository the handlers subsequently operate on. `Handler#stacks`/`#repository_name` resolves the target purely from `repository.full_name`, an independent field in the same attacker-controlled JSON body: [3](#0-2) 

`Repository.from_github_repo_name` then does a direct DB lookup by `owner/name` split out of that field, with no cross-check against the organization used to verify the signature: [4](#0-3) 

`PushHandler#process` (and equivalent handlers for `status`, `check_suite`, `membership`, `pull_request`, etc.) uses that mismatched `stacks` collection to act on the victim organization's stack: [5](#0-4) 

This is exactly the "organization that authenticated versus the repository that is written" binding break: the equality `verified_org(repository.owner.login) == acted_upon_repo.owner(repository.full_name)` is never enforced. Multi-org configuration is a first-class, documented feature (`docs/setup.md` "Using Multiple Github Applications"), where each organization has its own independent `app_id`/`private_key`/`webhook_secret`: [6](#0-5) 

### Impact Explanation
An attacker who is an administrator of Organization A (one legitimate, Shipit-integrated GitHub org, over which they have full control including their own app's `webhook_secret`) can craft a webhook payload where `repository.owner.login` = `"OrgA"` (so the HMAC check succeeds using their own known secret) but `repository.full_name` = `"OrgB/victim-repo"` (a completely different, unrelated organization's repository that is also configured in the same Shipit instance). The forged payload is then dispatched to handlers that operate on `OrgB`'s stack:
- A forged `status` event can inject a fabricated passing CI status for an arbitrary commit SHA in `OrgB`'s repository. Since `ci.require` gates deploys purely on stored statuses, and continuous-deployment/auto-merge stacks act on statuses, this can be used to make an unsafe or malicious commit appear CI-green and trigger an **unauthorized deploy** of `OrgB`'s stack — an explicitly listed Critical impact.
- A forged `push` event can force `GithubSyncJob` to run for `OrgB`'s stack with an attacker-chosen `expected_head_sha`.
- A forged `pull_request`/`membership` event can manipulate `OrgB`'s merge-queue/team state.

This crosses an organization boundary that the webhook signature scheme is supposed to enforce, without requiring any privilege on the victim organization.

### Likelihood Explanation
Requires the Shipit deployment to have multi-org support configured (a documented, supported configuration) and requires the attacker to control at least one of the configured organizations' webhook secret (i.e., be an admin of their own, legitimately-onboarded org). No access to the victim org, no GitHub write access to the victim repo, and no Shipit session/API token is needed — only knowledge of one's own org's webhook secret and the ability to send an HTTP POST to the public `/github` webhook endpoint. This is realistic in any Shipit instance shared across multiple, mutually-untrusting GitHub organizations.

### Recommendation
After verifying the HMAC signature, re-derive the "authenticated organization" and require that `repository.full_name.split('/').first` (or `organization.login`) matches the organization whose secret was used to verify the signature, rejecting the webhook (HTTP 422) on mismatch. This restores the binding between the verified signer and the resource acted upon.

### Proof of Concept
1. Configure Shipit with two GitHub Apps (`OrgA`, `OrgB`) per `docs/setup.md`'s multi-org example.
2. As an admin of `OrgA`, obtain `OrgA`'s `webhook_secret` (you legitimately control this app).
3. Build a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "OrgB/victim-repo",
    "owner": { "login": "OrgA" }
  }
}
```
4. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>` and POST it to `/github` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` resolves `repository_owner` → `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature check passes (attacker knows this secret).
6. `PushHandler#process` resolves `stacks` from `repository.full_name` = `"OrgB/victim-repo"`, and enqueues `GithubSyncJob`/updates state for `OrgB`'s stack — despite the request never having been authenticated for `OrgB`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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
```

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
