### Title
Webhook signature is verified against the org named in the payload while the acted-upon repository/team is resolved from separate, unchecked payload fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/`webhook_secret` to validate the HMAC signature against using `repository_owner`, a value read straight out of the untrusted JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). Once the signature check passes, the event is dispatched to handlers that independently resolve the *target* repository/team from other fields of the same untrusted body (`repository.full_name`, `organization.id`/`team.id`, etc.). Nothing binds "the org whose secret signed this request" to "the repository/team the handler is about to mutate."

### Finding Description
`verify_signature` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

The HMAC secret selected for verification is keyed by an attacker-controlled field of the very payload being verified. Once `head(422)` isn't hit, `create` dispatches unconditionally to registered handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [2](#0-1) 

Handlers then resolve the *target* independently from other payload fields, with no cross-check that this target belongs to the org that supplied the valid signature:
- `Handler#stacks` resolves by `payload.dig('repository', 'full_name')`: [3](#0-2) 
- `MembershipHandler#process` creates/updates a `Team` and adds/removes a `User` membership using `params.team.id` / `params.organization.login` / `params.member.login`, all payload-controlled, with no relation back to `repository_owner`: [4](#0-3) 
- `PushHandler#process` triggers `stack.sync_github` for whatever branch/stack matches the payload's `ref`/`repository.full_name`: [5](#0-4) 

Because Shipit explicitly supports multiple GitHub organizations, each with its own App/`webhook_secret` (see `test/dummy/config/secrets_double_github_app.yml` and `Shipit.github_organizations`), a party that legitimately controls a webhook secret for **one** configured organization (e.g. because they administer their own org's GitHub App installed on the same Shipit instance) can produce a validly-signed request (`verify_webhook_signature` succeeds using their own org's secret because `repository_owner` in the JSON says their own org) while every other field consumed by the handlers (`repository.full_name`, `organization.login`, `team.id`) names a *different*, victim org/repository/team tracked by the same Shipit instance. The equality the code implicitly assumes - "org that authenticated == repo/org/team that gets written" - never actually holds, because both sides are independently taken from the same attacker-supplied JSON body instead of being derived from one authenticated source.

### Impact Explanation
This breaks a deployment-trust binding explicitly called out in scope: "an organization that authenticated versus the repository that is written." Concretely, an attacker who only controls credentials for one configured GitHub org/App on a shared Shipit instance can:
- Force `GithubSyncJob`/`sync_github` for a stack belonging to an unrelated tracked repository (`push` event), driving unwanted commit ingestion and deploy-eligibility state for a repo they don't own.
- Via `membership`, create teams and add/remove arbitrary GitHub logins into a `Team` record that is authoritative for `User#authorized?` (`Shipit.github_teams`), which gates all Shipit access (`app/controllers/concerns/shipit/authentication.rb`, `force_github_authentication`). If the forged team maps onto an authorization-relevant team (matching name/`github_id` collision or an org admin later configuring that team as an authorized team), this is an escalation path into `Shipit.github_teams` authorization - explicitly listed as a High-severity impact category.
- Trigger `PullRequest` review-stack provisioning/archival handlers for repositories/PRs that don't belong to the signing org.

This is exactly analogous to the reported `unzap()` bug: code assumes a property ("the router already has approval", here "the signer org matches the acted-upon target") that is never actually enforced, so the trusted operation is performed against unintended/unauthorized state.

### Likelihood Explanation
Exploitability requires the attacker to control at least one legitimately configured GitHub App/org on the *same* multi-tenant Shipit deployment (a documented, supported configuration — see `docs/setup.md` and `secrets_double_github_app.yml`). No GitHub App private key, `ApiClient` token, or Shipit session is needed; the attacker only needs the ability to make GitHub emit (or to directly POST, mimicking GitHub) a webhook whose `X-Hub-Signature` is valid for their own org's `webhook_secret`, with other JSON fields altered to point at another org's repository/team. Since GitHub webhook signatures only cover the raw body content and are not aware of Shipit's per-org routing, and Shipit's webhook secret is often shared/known indirectly by whoever owns the sending App, this is a realistic misconfiguration-adjacent scenario for any Shipit instance serving more than one organization.

### Recommendation
Do not let any field of the untrusted payload determine both (a) which secret verifies the signature and (b) which repository/org/team is mutated, without cross-checking the two. Concretely:
- After signature verification succeeds for `repository_owner`, re-derive the "owner" that handlers use (`repository.full_name`'s owner, `organization.login`, `team`'s owning org) and assert it is byte-for-byte equal to the org whose secret validated the signature; reject (422) on mismatch.
- Alternatively/additionally, resolve the Shipit `Repository`/`Team` scoping via a per-organization-bound lookup (e.g., pass the verified organization into `Handler.call`/`stacks`/`find_or_create_team!` rather than re-reading it from the payload).

### Proof of Concept
Given a Shipit instance configured with two GitHub Apps/orgs, `attacker-org` (secret known to the attacker, e.g. because they administer that org's App) and `victim-org` (a separate tracked stack):

1. Attacker crafts a `membership` webhook JSON body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Shipit/authorized-team", "slug": "authorized-team", "url": "https://github.com/..." },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-github-login" },
  "repository": { "owner": { "login": "attacker-org" } }
}
```
2. Attacker computes `X-Hub-Signature` using `attacker-org`'s `webhook_secret` (which they legitimately possess) over this raw body, exactly as `Hook::DeliverySigner`/`GitHubApp#verify_webhook_signature` expect (`app/controllers/shipit/webhooks_controller.rb` lines 24-38, `lib/shipit/github_app.rb` lines 76-83).
3. POST to `/webhooks` with `X-Github-Event: membership` and that signature.
4. `verify_signature` looks up `Shipit.github(organization: 'attacker-org')` and successfully verifies, because the signature really was produced with `attacker-org`'s secret.
5. `MembershipHandler#process` runs using `params.team.id = 999` / `params.organization.login = 'attacker-org'` / `params.member.login`, creating/updating a `Team` row and adding the attacker's GitHub login as a member - independent of which org's key actually signed the request being otherwise unchecked against `team`/`organization` fields. If `id: 999` happens to collide with (or is later configured as) a team in `Shipit.github_teams`, the attacker is granted `authorized?` access to the whole Shipit instance. [1](#0-0) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-47)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandler < Handler
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
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
      end
    end
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
