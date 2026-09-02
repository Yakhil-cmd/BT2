### Title
Webhook signature is verified against `repository.owner.login`/`organization.login`, but event handlers act on the unrelated `repository.full_name` field, allowing an org whose webhook secret is authenticated to inject events for a completely different repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` computes the HMAC signature check using the GitHub App config keyed on `repository_owner`, which is read from `params.dig('repository','owner','login')` (falling back to `organization.login`). Once that signature check passes, `create` dispatches the *entire raw payload* to every registered handler for the event. Those handlers never re-check `repository.owner.login`; instead they derive the target repository from a completely different, unauthenticated field: `payload.dig('repository', 'full_name')` in `Handler#repository_name`, which is used by `Repository.from_github_repo_name` to look up the `Stack`(s) to act on.

### Finding Description
This is a binding break: the field covered by the cryptographic signature (`repository.owner.login` / `organization.login`, used only to select which org's `webhook_secret` to HMAC-check with) is not the same field the business logic subsequently trusts (`repository.full_name`) to decide *which repository/stack* is mutated.

- Signature check: [1](#0-0) , using `repository_owner` derived at [2](#0-1) .
- Handler dispatch passes the raw, fully attacker-controlled JSON body straight to handlers: [3](#0-2) .
- Every handler resolves the acted-upon repository from `repository.full_name`, not from `repository.owner.login`: [4](#0-3) .
- `Repository.from_github_repo_name` does a raw DB lookup on `owner/name` parsed out of that unauthenticated `full_name` string, with no cross-check against the signer's organization: [5](#0-4) .
- `PushHandler` uses this to trigger `Stack#sync_github` for the resolved stacks: [6](#0-5) .
- `StatusHandler` writes commit statuses purely by `sha` with no repository scoping at all beyond the `Commit.where(sha:)` match: [7](#0-6) .

Concretely: if an attacker controls (or is a legitimate member of) any GitHub organization `OrgA` that is configured in Shipit with a `webhook_secret` (this is a normal, low-privilege scenario for anyone who can trigger a real webhook delivery from `OrgA`, e.g. via a push to a repo in `OrgA` that they can write to, or by directly relaying a signed request), they can produce a validly-signed request where `repository.owner.login = "OrgA"` (so `verify_signature` passes using `OrgA`'s secret) while `repository.full_name = "OrgB/some-other-repo"` (a repository belonging to an entirely different, unrelated organization `OrgB` that is also configured in Shipit). Because handlers never compare `repository.owner.login` to `repository.full_name`'s owner segment, the forged event is processed as if it legitimately originated from `OrgB`.

### Impact Explanation
This breaks the "organization that authenticated vs. repository that is written" binding explicitly and enables:
- Injecting a fake `push` event for `OrgB/some-other-repo`, causing `Stack#sync_github` to run against `OrgB`'s stack with an `after` SHA of the attacker's choosing [6](#0-5) .
- Injecting fake `status` events that create passing CI statuses on arbitrary commits by `sha` alone, with no repository ownership check [7](#0-6) , which can be used to satisfy `ci.require` checks and enable an otherwise-blocked deploy on `OrgB`'s stack — an unauthorized deploy triggered from a lower-trust organization's credentials.

### Likelihood Explanation
Requires the attacker to be able to produce (or relay) a validly HMAC-signed webhook delivery for *any one* org configured in Shipit — a materially lower bar than compromising the target org (`OrgB`) itself, since GitHub webhook secrets are per-organization/app-installation and nothing in the controller ties the signing org to the repository being mutated.

### Recommendation
In `WebhooksController#verify_signature` / `Handler#repository_name`, enforce that the organization used to select and verify the webhook secret (`repository.owner.login`/`organization.login`) matches the owner segment of `repository.full_name` before any handler is allowed to act on it; reject the request (422) on mismatch.

### Proof of Concept
1. Ensure Shipit has two orgs configured with distinct `webhook_secret`s, `OrgA` and `OrgB`, each owning at least one repo/stack in Shipit.
2. As someone able to produce a signed webhook for `OrgA` (e.g., a collaborator on any `OrgA` repo, or anyone who can replay a real `OrgA` delivery), craft:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/target-repo"
  }
}
```
3. Sign the raw body with `OrgA`'s `webhook_secret` and send `X-Hub-Signature: sha1=<hmac>` with `X-Github-Event: push` to `/webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and passes [8](#0-7) .
5. `PushHandler#process` resolves stacks via `repository.full_name = "OrgB/target-repo"` [4](#0-3)  and triggers `sync_github` on `OrgB`'s stack, despite the request never being authenticated as originating from `OrgB`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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
