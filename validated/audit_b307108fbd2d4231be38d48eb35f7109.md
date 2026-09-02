## Title
Webhook signature verification is bound to `repository.owner.login`, but every downstream handler routes on the unverified `repository.full_name` / `organization.login` fields — ([File: app/controllers/shipit/webhooks_controller.rb])

## Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC against using `repository_owner`, derived from `params.dig('repository','owner','login')` (falling back to `organization.login`). Once that HMAC check passes, the raw JSON body is handed unmodified to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. None of the built-in handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`, PR handlers) re-check that the organization whose secret validated the signature matches the organization/repository the handler actually acts on — they independently read `repository.full_name` (via `Handler#repository_name`) or `organization.login` (in `MembershipHandler`) to select the target `Stack`/`Team`. In a multi-organization Shipit deployment (explicitly supported per `config/secrets.development.example.yml`), this breaks the binding: `organization authenticated (via owner.login → its webhook_secret) == repository/organization written (via full_name/organization.login)`.

## Finding Description
`app/controllers/shipit/webhooks_controller.rb`:
```
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
``` [1](#0-0) [2](#0-1) 

The controller then dispatches the *entire, attacker-suppliable* JSON body to handlers:
```
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Handlers resolve their target purely from `repository.full_name`, a field distinct from the one used for signature-org selection:
```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`Repository.from_github_repo_name` simply looks up `owner/name` from that field: [5](#0-4) 

`PushHandler` uses that lookup to trigger a git sync for the matched stack: [6](#0-5) 

`MembershipHandler` similarly trusts `params.organization.login` directly (a sibling top-level field, also outside the org-selection logic) to create/modify `Team` records and team memberships that feed `Shipit.github_teams` authorization (`User#authorized?` in `app/models/shipit/user.rb`): [7](#0-6) 

Shipit explicitly supports hosting multiple independent GitHub organizations from one instance, each with its own `webhook_secret`, as shown by the documented multi-org config schema: [8](#0-7) 

**Binding broken:** `organization authenticated (repository.owner.login → its webhook_secret)` != `organization/repository actually written (repository.full_name / organization.login used by the handler)`.

**Before the exploit:** GitHub always produces internally-consistent payloads (an event for `orgA/repoX` always has `repository.owner.login == "orgA"` and `repository.full_name == "orgA/repoX"`), so in legitimate deliveries the two fields always agree.

**After the exploit:** The webhook endpoint is a raw, unauthenticated HTTP POST endpoint (`skip_before_action :verify_authenticity_token`, no session/API-client requirement) that accepts any hand-crafted JSON body plus an `X-Hub-Signature` header. Because the signature is only proven to have been generated with *some* configured organization's `webhook_secret` — not proven to correspond to the repository the payload claims to modify — an actor who legitimately possesses Organization A's `webhook_secret` (e.g., by being an owner/admin of their own GitHub organization A, which is one of potentially several orgs configured on the shared Shipit instance) can forge a POST with `repository.owner.login = "orgA"` (to select and pass Org A's HMAC check) while setting `repository.full_name = "orgB/repoY"` (a repository belonging to a different, unrelated organization B also hosted on the same instance). The signature check passes, and `PushHandler`/`StatusHandler`/`CheckSuiteHandler`/PR handlers then operate on Org B's stack.

## Impact Explanation
This is a cross-organization write achieved purely by possessing credentials for one tenant of a shared multi-org Shipit instance:
- `push` event: forged `sync_github`/`GithubSyncJob` calls on an unrelated org's stack, and forged `status`/`check_suite` events can flip a foreign commit's CI/check state to "success," which (per `Commit#add_status` and continuous-deployment logic referenced in `stack.schedule_merges`) can enable an **unauthorized deploy** of that commit on Organization B's stack without ever authenticating against Organization B's GitHub App.
- `membership` event: forged team/member creation lets an Org-A-credentialed actor fabricate `Team`/`Membership` records that feed directly into `Shipit.github_teams` authorization checks in `User#authorized?`, i.e., **escalation into `Shipit.github_teams` authorization** for an org they don't belong to.

Both outcomes match the in-scope Critical/High impact categories ("an unauthorized deploy, rollback or merge" and "escalation into `Shipit.github_teams` authorization").

## Likelihood Explanation
Requires only: (a) the target Shipit instance being configured for multiple GitHub organizations (an explicitly documented, supported configuration), and (b) the attacker legitimately controlling one of those organizations' own webhook secret (ordinary admin capability of their own GitHub org/App, not privileged access to Shipit or to the victim organization). No Shipit session, `ApiClient` token, or GitHub App private key is needed — only the ability to compute a valid HMAC for the org they already own, which they always have as that org's administrator.

## Recommendation
After `verify_webhook_signature` succeeds for the organization determined by `repository_owner`, enforce that every field the handlers act on (`repository.full_name`'s owner segment, `organization.login`) is consistent with the verified `repository_owner`/`github_app.organization` before dispatching to handlers — i.e., reject the request (422) if `repository.full_name.split('/').first != repository_owner` (case-insensitive) or if `organization.login` disagrees with the verified organization.

## Proof of Concept
1. Shipit instance configured with two organizations, e.g. `OrgA` (attacker-administered, webhook_secret known to attacker) and `OrgB` (victim, unrelated), per the multi-org `github:` config block.
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already present as a status='success' commit on OrgB's stack>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/repoY" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>` (they legitimately know `OrgA`'s secret).
4. POST to `/github/webhooks` (or engine-mounted webhook path) with `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and the HMAC validates → request proceeds.
6. `PushHandler#stacks` resolves `Repository.from_github_repo_name("OrgB/repoY")` and calls `stack.sync_github(expected_head_sha: ...)` on Organization B's stack, despite the request never having been authenticated against Organization B's GitHub App/webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
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
