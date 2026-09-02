### Title
Webhook signature verification keys off `repository.owner.login`/`organization.login` while every event handler trusts a separate, unvalidated field (`repository.full_name`, `organization.login`) to decide which Team/Stack/Repository is mutated — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify the HMAC signature against using a field read straight out of the untrusted, attacker-controlled JSON body (`repository.owner.login`, falling back to `organization.login`). None of the downstream webhook handlers (`PushHandler`, `MembershipHandler`, `PullRequest::*Handler`) re-derive the acting scope from that same verified field — they instead read `repository.full_name` (a separate string that is not required to be consistent with `repository.owner.login`) or `organization.login` directly to decide which `Stack`/`Repository`/`Team` record is written. In a multi-GitHub-App Shipit deployment (the documented `config/secrets.yml` schema with one webhook secret per organization), an attacker who legitimately knows the webhook secret for *one* configured organization can forge an HMAC-valid request whose "verified" owner field points at their own org while the "acted-on" field points at a different, victim organization/repository, breaking the binding between the organization whose signature is checked and the organization/repository whose state is actually written.

### Finding Description
The webhook signature check is: [1](#0-0) [2](#0-1) 

`repository_owner` is computed purely from the JSON body (`params.dig('repository','owner','login') || params.dig('organization','login')`), and `Shipit.github(organization: repository_owner)` picks the webhook secret used for HMAC verification: [3](#0-2) 

Shipit explicitly supports one webhook secret per GitHub organization, each independently configured/administered: [4](#0-3) 

Once the signature passes, `create` dispatches the *entire raw JSON body* to handlers, with no further cross-check that other fields in the payload agree with `repository_owner`: [5](#0-4) 

Handlers derive the object to act on from different sub-fields of the same body:
- `PushHandler`/`Handler#stacks` resolves the `Stack` via `repository.full_name` (owner+name concatenated), not `repository.owner.login`: [6](#0-5) [7](#0-6) 
- `MembershipHandler` sets `team.organization = params.organization.login` and adds an arbitrary `member.login` to that team: [8](#0-7) 

There is no code anywhere that asserts `repository.owner.login == repository.full_name.split('/').first`, nor that `organization.login == repository.owner.login` when both keys are present. `Repository.from_github_repo_name` simply parses whatever string is supplied: [9](#0-8) 

**Break of trust binding (as equality):** the engine implicitly assumes
`organization_whose_secret_signed_the_request == organization/repository_that_is_written`,
but the controller verifies the signature using `repository.owner.login` (or `organization.login`) while handlers act on `repository.full_name` or `organization.login` read independently from the same untrusted body. Because these are two separate JSON fields with no cross-field validation, an attacker who knows the webhook secret of *any one* configured organization (e.g., an org admin of "attacker-org" in a Shipit instance serving multiple orgs) can construct a raw POST body such as:

```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```

and sign it with `attacker-org`'s webhook secret. `verify_signature` computes `repository_owner = "attacker-org"`, fetches `attacker-org`'s webhook secret, and the HMAC matches (since the attacker used that exact secret) — so the request is accepted. `PushHandler` then resolves the stack using `repository.full_name = "victim-org/victim-repo"`, triggering `stack.sync_github(expected_head_sha: ...)` for a repository the attacker does not control and whose org's webhook secret they never possessed.

Similarly, for `membership` events (which have no `repository` key at all, only `organization`), `repository_owner` and the handler's `params.organization.login` happen to be the *same* field in that specific event type, so that particular path is not exploitable this way — but this only underscores that the controller's guard is coincidental per-event-type, not a systematically enforced invariant across all handlers, and any handler (current or future, including third-party ones registered via `Shipit::Webhooks.register_handler`) that reads `repository.full_name`, `organization.login`, or any other body field independently from `repository_owner` inherits this same gap.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary called out as in-scope. In a multi-tenant Shipit deployment (the officially documented multi-org `secrets.yml` layout), a party who administers/knows the webhook secret for one onboarded GitHub organization can:
- Force `GithubSyncJob`/`sync_github` calls against a victim's `Stack` (`repository.full_name` spoofing in `push`), potentially affecting deploy/CI state tracked by Shipit for a repository they don't own.
- More broadly, any handler that trusts a body field not covered by the owner-derived signature check is susceptible to cross-repository/cross-organization state writes without holding that organization's actual webhook secret.

This matches the High-severity category "escalation into `Shipit.github_teams` authorization" / unauthorized writes to stack state via a forged but "validly signed" webhook, since the validation performed does not actually bind the verified secret to the object being mutated.

### Likelihood Explanation
Requires the attacker to already know one organization's webhook secret in a multi-organization Shipit deployment (i.e., they are a legitimate, if unprivileged relative to the target org, admin/operator of a *different* onboarded GitHub App/org sharing the same Shipit instance) — this is exactly the kind of "unprivileged-attacker" scenario the scope calls for (no Shipit session, API token, or the *target* org's secret is needed). Single-organization deployments (the default, non-multi-org config) are not exposed since there is only one webhook secret and `repository_owner` always maps to it. Likelihood is Medium: it requires the multi-org deployment pattern that Shipit explicitly documents and supports, but no other privilege.

### Recommendation
- After signature verification, re-validate that every organization/owner-bearing field consumed by a handler (`repository.owner.login`, `repository.full_name`'s owner segment, `organization.login`) is consistent with the `repository_owner` value used to select the verifying secret; reject the webhook (422) on mismatch.
- Alternatively, make `Handler#stacks`/`repository_name` and all org-scoped handlers derive their target strictly from the already-verified `repository_owner`, rather than re-reading raw body fields independently.
- Add an explicit cross-field consistency check in `WebhooksController#verify_signature` or `#create` (e.g., `repository.full_name.split('/').first == repository.owner.login`) before dispatching to handlers.

### Proof of Concept
1. Deploy Shipit with the documented multi-org `github:` config (`somegithuborg`, `someothergithuborg`, each with its own `webhook_secret`), onboarding both `attacker-org` and `victim-org`.
2. As an operator with knowledge of `attacker-org`'s `webhook_secret` (legitimately configured for that org), craft:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "deadbeef",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, raw_body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, fetches `attacker-org`'s app/secret, and the signature check passes (`Shipit::GitHubApp#verify_webhook_signature`, [3](#0-2) ).
5. `PushHandler#process` resolves stacks via `Handler#stacks` → `Repository.from_github_repo_name("victim-org/victim-repo")` ( [6](#0-5)  and [9](#0-8) ), and calls `stack.sync_github(expected_head_sha: "deadbeef")` on the victim's stack — despite the request only ever being signed with `attacker-org`'s secret.

Note: I was not able to execute this against a live instance (no filesystem/terminal access in this mode); the analysis is based on static reading of the cited files. If further confirmation is needed (e.g., exact downstream effects of `sync_github` on production data), a Devin session with repository access should be used to reproduce this end-to-end in a test Shipit instance.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L182-209)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
