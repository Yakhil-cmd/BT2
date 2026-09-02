I have enough evidence to write the finding now.

### Title
Webhook signature verification organization is decoupled from the organization/repository the event handlers actually act on, enabling cross-tenant status forgery and team membership escalation - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret and validates the HMAC using only `repository_owner` (`repository.owner.login`, falling back to `organization.login`). Every downstream `Webhooks::Handlers::*` class then re-parses the *same raw JSON body* and independently pulls whichever fields it needs (`repository.full_name`, `organization.login`, `sha`, etc.) to decide which `Stack`, `Team`, or `Commit` to mutate — with no re-check that those fields belong to the organization whose secret validated the signature. This mirrors the reported bug class ("a value trusted implicitly, with no correctness check tying it back to the verified source of truth"): the equality that should hold — `verified_signature_org == acted_upon_org/repository` — is never enforced.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` verifies the signature like this: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` picks the `webhook_secret` for whatever organization name is embedded in the attacker-supplied JSON body (`repository.owner.login`, or `organization.login` if `repository` is absent), and `verify_webhook_signature` only checks that the raw body's HMAC matches that org's secret: [3](#0-2) 

Once verification passes, `WebhooksController#create` dispatches the *entire* raw body to the handler, unchanged: [4](#0-3) 

Handlers never re-derive or re-check the organization against the one used for signature verification:

- `StatusHandler` matches purely on `sha`, globally, with no organization/repository scoping at all: [5](#0-4) 

- `MembershipHandler` derives the `Team#organization` from `params.organization.login`, a field independent of `repository.owner.login` used for verification: [6](#0-5) 

- The base `Handler#stacks`/`repository_name` uses `repository.full_name`, which is also never cross-checked against `repository.owner.login`: [7](#0-6) 

Because `repository_owner` and `repository.full_name`/`organization.login` are read from independent keys of the same attacker-controlled JSON body, an admin of one organization onboarded to a shared Shipit installation (`repository_owner` = Org A, whose `webhook_secret` they legitimately possess) can forge a webhook whose HMAC is valid for Org A, while setting the payload's `organization.login` (membership event) or `sha` (status event) to target a completely different organization/repository (Org B) also tracked by the same Shipit instance. The binding `verified_org == acted_upon_org` is broken.

### Impact Explanation
- **Status forgery (Critical — unauthorized deploy/merge):** `StatusHandler#process` matches `Commit.where(sha: params.sha)` with zero scoping by stack/org. Since GitHub commit SHAs are public, an attacker who only controls Org A's webhook secret can forge a `status` event (signed with Org A's secret) naming the SHA of a real commit tracked under Org B's stack, injecting an arbitrary `success` state. `Commit#add_status` then calls `stack.schedule_merges if new_status.pending? || new_status.success?` [8](#0-7) , which can unlock Org B's merge queue / deploy safety checks despite Org B's real CI never reporting success — an unauthorized merge/deploy path.
- **Team/authorization escalation (High/Critical — `Shipit.github_teams` bypass):** `MembershipHandler` creates/updates a `Team` scoped to `params.organization.login` and adds an arbitrary `member.login` to it, independent of the organization whose secret validated the request. If that team's handle matches a configured `Shipit.github_teams` entry, `User#authorized?` [9](#0-8)  grants full application access to any attacker-chosen GitHub login, bypassing the intended organization-membership gate in `force_github_authentication` [10](#0-9) .

### Likelihood Explanation
Requires the Shipit instance to onboard more than one GitHub organization (documented, supported multi-org configuration in `docs/setup.md`) and requires the attacker to know/hold the legitimate webhook secret for at least one of the onboarded organizations (e.g., as an admin of their own org's GitHub App/webhook config) — a realistic scenario for shared/multi-tenant Shipit deployments, and the intended threat model already assumes such an actor is untrusted with respect to other tenants' repositories.

### Recommendation
- In `WebhooksController`, after computing `repository_owner` from the body, re-verify that every organization-identifying field consumed by the dispatched handler (`repository.full_name`'s owner, `organization.login`) matches `repository_owner` before dispatch, or pass the verified organization explicitly into `Handler.call` so handlers can enforce it rather than re-reading untrusted payload fields.
- In `StatusHandler`, scope `Commit.where(sha:)` to stacks whose `Repository` belongs to the verified organization.
- In `MembershipHandler`, verify `params.organization.login` equals the organization used to validate the signature before creating/updating a `Team` or adding members.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `docs/setup.md` "Using Multiple Github Applications").
2. Attacker is an admin of `org-a` and thus knows `org-a`'s `webhook_secret` (e.g., can trigger genuine webhooks from their own repo).
3. Attacker looks up (public) the SHA of the current HEAD commit of an `org-b` stack tracked by the same Shipit instance.
4. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, body:
```json
{
  "repository": { "owner": { "login": "org-a" } },
  "sha": "<org-b-head-sha>",
  "state": "success",
  "context": "ci/forced"
}
```
   signed (`X-Hub-Signature`) with `org-a`'s `webhook_secret`.
5. `verify_signature` passes (Org A's secret matches Org A's owner field). `StatusHandler#process` finds the commit by SHA regardless of stack/org and creates a `success` `Status`, triggering `stack.schedule_merges` on the `org-b` stack — an unauthorized merge/deploy trigger the attacker has no legitimate access to.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
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
