## Title
Webhook signature verification checks the payload's `repository.owner.login` while all event handlers act on `repository.full_name`, allowing a webhook signed by one GitHub organization's secret to trigger actions on another organization's stack - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on `repository.owner.login` (with a fallback to `organization.login`), but every webhook handler resolves the `Stack`/`Repository` it actually acts on using the separate `repository.full_name` field. These two payload fields are never cross-checked, so a request can be crafted where the verified organization and the affected repository/stack differ.

### Finding Description
`verify_signature` computes the org used for signature verification from the payload itself, independent of the field used to locate the resource that is mutated: [1](#0-0) [2](#0-1) 

Meanwhile, `Shipit::Webhooks::Handlers::Handler` (the base class every handler, including `PushHandler`, inherits from) resolves the target repository/stack using a *different* field, `repository.full_name`: [3](#0-2) 

`PushHandler#process` uses that `stacks` scope directly to call `stack.sync_github`, which fetches commits and enqueues `GithubSyncJob`: [4](#0-3) 

For genuine GitHub-originated webhooks, `repository.owner.login` and the owner segment of `repository.full_name` are always consistent, so this discrepancy is invisible in normal operation. But since Shipit supports multiple GitHub Apps/organizations configured under distinct top-level keys with separate `webhook_secret`s (as documented), and the webhooks endpoint (`/webhooks`) is unauthenticated and reachable by anyone who knows a valid organization's secret for their own installation: [5](#0-4) 

an attacker who legitimately controls one configured GitHub organization (and thus knows that organization's own `webhook_secret`) can submit a forged JSON payload directly to `/webhooks` with:
- `repository.owner.login` = their own org (so `verify_signature` selects and verifies against their own known secret), and
- `repository.full_name` = `"victim-org/victim-repo"` (an unrelated stack configured in the same Shipit instance).

The equality that should hold is:
`verified_org (repository.owner.login used for HMAC check) == acted_upon_repo_org (owner segment of repository.full_name used for stack lookup)`

Before the attack this equality always holds (GitHub always produces consistent payloads). The forged request breaks it: the signature is valid for the attacker's own org, but the handler acts on a stack belonging to a different, unrelated organization.

### Impact Explanation
This crosses a repository/organization trust boundary without requiring any Shipit session, API token, or GitHub App credentials belonging to the victim organization — only knowledge of a secret the attacker legitimately possesses for their own configured organization. Depending on which webhook event/handler is targeted, this can force unauthorized processing of another organization's stack (e.g., triggering `GithubSyncJob` and `CacheDeploySpecJob` for a victim repository via `PushHandler`, or manipulating pull-request/review-stack state for a victim repository via the pull-request handlers, all of which key off `repository.full_name` rather than the verified org). This matches the "unauthorized deploy/rollback/merge" and "authorization escalation across repositories" class of impact, since it lets a party authenticated only for organization A's webhook drive write-affecting jobs scoped to organization B's stack.

### Likelihood Explanation
Likelihood is high in any Shipit deployment configured with the documented multi-organization GitHub Apps feature: any org admin able to create/install a GitHub App (or simply knowing their own org's configured `webhook_secret`) can craft and POST an arbitrary JSON body to the public `/webhooks` endpoint with a correctly computed `X-Hub-Signature`, since no additional binding between `repository.owner.login` and `repository.full_name` is enforced.

### Recommendation
In `WebhooksController#verify_signature`, after successfully verifying the signature, cross-check that the organization used for verification (`repository_owner`) matches the owner segment of `repository.full_name` (and of `organization.login` if present) before dispatching to handlers. Alternatively, have handlers derive the repository/stack strictly from the same field that was cryptographically bound to the verified secret, rather than trusting a second, unauthenticated payload field.

### Proof of Concept
1. Shipit is configured with GitHub Apps for two organizations, `attacker-org` (attacker's own, webhook secret known to them) and `victim-org` (contains a Stack `victim-org/victim-repo`), per the multi-org `secrets.yml` layout in `docs/setup.md`.
2. Attacker computes `signature = HMAC-SHA1(attacker-org's webhook_secret, body)` for the following JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
3. Attacker sends `POST /webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<signature>`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and verifies successfully against the attacker's own known secret.
5. `PushHandler#process` resolves `stacks` from `repository.full_name` = `"victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for the victim stack — a stack the attacker has no authorization over, despite the request only being signed by an unrelated organization's secret. [6](#0-5) [3](#0-2) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** docs/setup.md (L184-209)
```markdown
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
