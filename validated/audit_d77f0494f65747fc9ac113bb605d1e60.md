### Title
Webhook status/check-suite handlers trust the payload's `repository`/`sha` fields independently of the organization used for signature verification, enabling cross-tenant CI status forgery - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC key to validate a webhook by reading `repository.owner.login` (or `organization.login`) straight out of the *unverified* JSON body, then hands the same untrusted body to event handlers that act on a completely different field of that body (`repository.full_name`) or, in the case of `StatusHandler`, on no repository field at all. This is the same class of bug as the Fei Pool `stakedBalance`/`totalStaked` drift: two values that are supposed to move together (“the org whose secret authenticated this request” and “the repo/commit the request is allowed to mutate”) are read from independent, attacker-controlled parts of the same payload and never cross-checked.

### Finding Description
`verify_signature` picks the signing secret using a value taken from the raw JSON body before the signature has been checked: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization: repository_owner)` looks up a *per-organization* `webhook_secret` (multi-org configuration is explicitly documented/supported: [3](#0-2) ). Once the HMAC check passes for whichever organization's secret was selected, the same raw payload is forwarded unchanged to every handler: [4](#0-3) 

`Handler#stacks`/`#repository_name` reads a *different* key of the same payload (`repository.full_name`) to decide which `Stack`/`Repository` the event applies to — it is never checked against `repository.owner.login`, the field that was actually used to pick the signing secret: [5](#0-4) 

`StatusHandler` is worse: it doesn't consult `repository` at all, it matches purely by commit SHA across the entire installation: [6](#0-5) 

```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

There is no scoping to the repository/organization whose secret authenticated the webhook. `CheckSuiteHandler` at least scopes to `stacks` (derived from `repository.full_name`), but that field is still never reconciled with `repository.owner.login` used for authentication: [7](#0-6) 

Binding that should hold as an equality but doesn't:
`organization_that_signed_the_request (repository.owner.login used in verify_signature) == organization_that_owns_the_repository/commit_being_mutated (repository.full_name / commit.stack.repository used in the handler)`.

Because both sides are read from the same attacker-suppliable JSON body, and only the first is protected by the HMAC check, an attacker who legitimately administers **any one** organization/GitHub App configured on a shared Shipit instance (and therefore legitimately knows *that org's own* `webhook_secret` — not the victim's) can produce a validly-signed webhook whose `repository.owner.login` is their own org (so it passes `verify_signature`) while its `sha`/`full_name` payload fields point at a victim organization's commit/stack.

### Impact Explanation
`StatusHandler` writes a `CommitStatus` for any commit matching the given SHA anywhere in the Shipit instance, with no ownership check. Commit statuses feed the `ci.require` deploy-safety gate documented for `shipit.yml`, so an attacker can forge a `success` status for a required CI context on a commit belonging to a repository/organization they do not own, allowing that commit to satisfy CI requirements and be deployed even though it never actually passed CI — an unauthorized deploy / cross-tenant write, matching the Critical/High impact bar (“cross-repository writes” / “an unauthorized deploy”). `CheckSuiteHandler`/`PushHandler` are exposed to the same organization/repository field mismatch, though they at least filter through `stacks`, reducing (but not eliminating) blast radius since `repository.full_name` is still attacker-controlled and unchecked against the authenticating org.

### Likelihood Explanation
This requires the attacker to control (i.e., legitimately administer) at least one GitHub organization/App that is registered on the same shared Shipit instance as the victim — a realistic scenario for any Shipit deployment serving multiple organizations/teams, which is an explicitly documented and supported configuration (`config/secrets.development.example.yml`, README multi-org example). No access to the victim's repository, secret, or Shipit account is required — only the attacker's own, unprivileged-relative-to-the-victim org credentials.

### Recommendation
After verifying the webhook signature, re-derive the repository/organization strictly from the same field that was used to select the signing key (`repository.owner.login`), and have every handler validate that `repository.full_name`'s owner segment (and, for `StatusHandler`, the actual `Commit#stack.repository`) matches that authenticated organization before mutating any records. Reject the webhook if the two disagree, mirroring the FeiPool fix of keeping `stakedBalance` and `totalStaked` in lockstep instead of letting them diverge.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` (attacker-controlled, attacker knows `webhook_secret_a`) and `org-b` (victim), as supported by `config/secrets.development.example.yml`.
2. Victim has a stack tracking `org-b/victim-repo`, with `shipit.yml` containing `ci.require: [my-ci-context]`, and a pending/red commit `abc123` known publicly (e.g., a public GitHub repo commit SHA).
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": {"owner": {"login": "org-a"}, "full_name": "org-a/whatever"},
  "sha": "abc123",
  "state": "success",
  "context": "my-ci-context"
}
```
signed with `webhook_secret_a` (attacker's own secret) in `X-Hub-Signature`.
4. `verify_signature` resolves `repository_owner` = `org-a`, validates successfully against `webhook_secret_a`.
5. `StatusHandler#process` runs `Commit.where(sha: "abc123")`, finds the victim's commit (no ownership check against `org-a`), and calls `create_status_from_github!`, marking `my-ci-context` as `success` on `org-b`'s commit — satisfying the victim stack's `ci.require` gate despite the attacker having no relationship to `org-b`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
