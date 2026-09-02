### Title
Webhook signature verification binds to `repository.owner.login`, but the write path resolves the target repository via the unrelated `repository.full_name` field — allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` taken directly from the unauthenticated JSON body. Once verification succeeds, the very same JSON body is handed to event handlers, which resolve the actual `Repository`/`Stack` to mutate using a *different* field, `repository.full_name`, that is never cross-checked against `repository.owner.login`. In a multi-organization Shipit deployment (each org has its own GitHub App and `webhook_secret`, as documented), an attacker who controls/administers one onboarded organization's GitHub App can forge a payload whose `owner.login` matches their own org (so their own known `webhook_secret` verifies) while `full_name` points at a repository belonging to a different organization, causing writes to that other organization's stack.

### Finding Description
The signature check is:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`repository_owner` is extracted from the request body itself before any authentication has taken place, and is used purely to pick which org's `webhook_secret` to HMAC-verify the raw body against, via `GitHubApp#verify_webhook_signature`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'
  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
``` [2](#0-1) 

Once `verify_signature` passes, `create` dispatches the **same raw JSON body** to handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Handlers such as `PushHandler` resolve the actual target `Repository`/`Stack` using the *unrelated* field `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [5](#0-4) 

`repository.owner.login` (used to select the authenticating secret) and `repository.full_name` (used to select the repository actually written to) are two independent, attacker-controlled strings inside the same unauthenticated JSON body — nothing in the code enforces that `full_name` starts with `owner.login/`. This is exactly the class of bug described in the report: a parameter used to authorize/select context (the interest-rate parameters / here, the authenticating organization) is decoupled from the parameter that the subsequent operation actually acts on (the accrual period / here, the repository actually written).

Shipit explicitly supports multiple GitHub Apps, one per organization, each with its own `webhook_secret`: [6](#0-5) 

### Impact Explanation
An attacker who is an administrator of *any* organization onboarded onto a shared multi-org Shipit instance (and thus legitimately knows that org's own `webhook_secret`, which they fully control since they created/installed that GitHub App) can forge a webhook body with `repository.owner.login` set to their own org (to pass signature verification with a secret they know) and `repository.full_name` set to `"other-org/other-repo"` for a repository they do not control. The forged, validly-signed request is then processed by handlers (`push`, `status`, `check_suite`, etc.) against the *other* organization's stack — e.g. forging `push` events to advance `sync_github`, or forging `status`/`check_suite` events to mark commits as passing CI, which can unblock deploys/merges for a repository outside the attacker's own scope. This is a cross-repository write / authentication-bypass class issue.

### Likelihood Explanation
Requires the deployment to configure more than one GitHub organization/App (a documented, supported configuration) and requires the attacker to control at least one onboarded organization's own GitHub App webhook secret — a low bar for that attacker relative to the target organization, since App owners always have access to their own app's webhook secret. No GitHub write access to the victim org, no Shipit session, and no privileged Shipit account are required, satisfying the "unprivileged attacker" scope.

### Recommendation
After signature verification, re-derive `repository_owner` again from the verified payload and cross-check that `repository.full_name`'s owner segment matches the organization whose secret was used to verify the signature, rejecting the webhook (422) on mismatch. Alternatively, verify the signature using the secret associated with the resolved `Repository`'s actual owner (derived server-side from `full_name`, then looked up in Shipit's own `Repository`/`Stack` records) rather than trusting the payload's `owner.login` field at all.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `OrgA` and `OrgB`, each with its own GitHub App and distinct `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications"). [6](#0-5) 
2. As an administrator of `OrgA`'s own GitHub App, the attacker knows `OrgA`'s `webhook_secret`.
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already existing in OrgB/target-repo>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/target-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and verifies successfully because the attacker used `OrgA`'s real secret. [7](#0-6) 
6. `create` parses the body and dispatches to `PushHandler`, which resolves the stack via `repository.full_name = "OrgB/target-repo"` and calls `stack.sync_github(expected_head_sha: ...)` — mutating `OrgB`'s stack state despite the attacker never having presented a credential valid for `OrgB`. [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
