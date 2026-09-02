### Title
Cross-organization webhook forgery via authenticated-org/written-repository mismatch - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a request's HMAC signature against based on `repository_owner`, taken from the JSON payload itself. The handlers that actually act on the payload (e.g. `Shipit::Webhooks::Handlers::Handler#repository_name`, used by `PushHandler`, `StatusHandler`, and the `PullRequest::*Handler`s) resolve the target `Repository`/`Stack` from a different field of the same attacker-supplied payload: `repository.full_name`. Nothing ties these two fields together, so the "organization whose secret authenticated the request" is not the same as "the repository the handler ultimately writes to."

### Finding Description
In a multi-tenant `Shipit.github` config (per-organization `webhook_secret`s, see `Shipit.github_app_config`), `verify_signature` does: [1](#0-0) 
where `repository_owner` is read straight from the untrusted payload: [2](#0-1) 

The signature is only checked to prove the request was signed with *some* organization's secret — specifically the organization named in `repository.owner.login` (or `organization.login`) inside the JSON body, which the attacker controls. Once verification passes, the same raw `params` are dispatched to handlers: [3](#0-2) 

Every handler resolves its target stacks via `repository_name`, taken from an independent field of the payload, `repository.full_name`, with no cross-check against `repository_owner`: [4](#0-3) 

`Repository.from_github_repo_name` then does a plain lookup by owner/name parsed out of that attacker-controlled string: [5](#0-4) 

So a user who legitimately controls one onboarded GitHub organization/App installation (and thus knows its `webhook_secret`) can HMAC-sign an arbitrary JSON body themselves and POST it directly to the Shipit webhooks endpoint, setting `repository.owner.login`/`organization.login` to *their own* org (so `verify_signature` picks their own known secret and passes) while setting `repository.full_name` to a victim organization's repository. Handlers such as `PushHandler` then look up and mutate the victim's stacks: [6](#0-5) 
or `StatusHandler` writes fabricated commit statuses for arbitrary commit shas across any stack: [7](#0-6) 
and the `PullRequest::ClosedHandler` can archive another org's review stack: [8](#0-7) 

This exactly matches the analog class called out in scope: "an organization that authenticated versus the repository that is written" — the equality `organization_that_signed == repository_being_written_to` is never enforced, only `organization_that_signed == organization_named_in_payload_owner_field`, and that owner field is disjoint from `repository.full_name`.

### Impact Explanation
An attacker who controls (or has been granted, e.g. as an org member with app-install rights) one tenant's webhook secret in a multi-org Shipit deployment can forge GitHub-shaped events that are processed as if they came from any other onboarded repository. Depending on handler reached, this enables: injection of fabricated commit statuses (`StatusHandler`) that can gate/unblock deploys on a victim stack, forced archiving of a victim's review stack (`PullRequest::ClosedHandler#process` → `review_stack.archive!`), tampering with a victim's tracked pull request metadata (`PullRequest::EditedHandler`), and forcing `PushHandler` to trigger `stack.sync_github` against a victim stack/branch outside the attacker's control. This is a cross-tenant authorization boundary break inside the engine's own webhook trust model — it doesn't require the GitHub webhook secret of the victim, only of any single onboarded tenant.

### Likelihood Explanation
Exploitability requires a multi-organization `secrets.github` configuration (per-organization GitHub App/secret), which is a documented, supported configuration path (`Shipit.github_app_config`, `TOP_LEVEL_GH_KEYS`). Given that, the attack requires no GitHub access at all beyond knowing one's own org's webhook secret (which any org admin who set up their own GitHub App integration would possess) and the ability to send an HTTP POST with a computed HMAC — a purely unprivileged-attacker capability with no session, `ApiClient` token, or repository write access needed.

### Recommendation
After signature verification, enforce that the organization used to select the verifying secret (`repository_owner`) matches the owner encoded in `repository.full_name` (and in `organization.login` if present) before dispatching to any handler. Reject the request (422) on mismatch instead of trusting `full_name` blindly in `Handler#repository_name`.

### Proof of Concept
1. Deploy Shipit with a multi-tenant `secrets.github` config containing two organizations, `attacker-org` (secret known to the attacker) and `victim-org` (a legitimate onboarded stack, e.g. `victim-org/victim-repo`).
2. Attacker crafts a JSON body mimicking a `push` event:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, raw_body)>` and sends `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')` and verifies successfully against the attacker's own known secret. [1](#0-0) 
5. `PushHandler#process` resolves `stacks` via `repository_name` → `payload.dig('repository','full_name')` = `victim-org/victim-repo`, and calls `stack.sync_github(expected_head_sha: 'deadbeef...')` on the victim's stack, despite the request never being signed by `victim-org`'s secret. [6](#0-5)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
