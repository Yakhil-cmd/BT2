Confirmed: `Handler#stacks` and `Handler#repository_name` derive the target repository purely from `payload.dig('repository', 'full_name')` [1](#0-0) , while `WebhooksController#verify_signature` selects which organization's secret to check against using a *different* payload field, `repository.owner.login` (falling back to `organization.login`) [2](#0-1) . These two fields are never cross-validated against each other.

### Title
Webhook organization used for signature verification is not bound to the repository the event actually mutates - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a webhook's HMAC signature using `repository_owner`, computed as `params.dig('repository','owner','login') || params.dig('organization','login')` [3](#0-2) . Once the signature passes, `WebhooksController#create` dispatches the *entire, attacker-suppliable* JSON body to the matching event handlers [4](#0-3) . Those handlers (`PushHandler`, `StatusHandler`, `MembershipHandler`, `CheckSuiteHandler`, pull-request handlers, etc.) resolve the actual `Stack`/`Repository`/`Team` to mutate from a *different* field of the same payload: `payload.dig('repository', 'full_name')` via `Handler#repository_name`/`#stacks` [1](#0-0) , or `params.organization.login` in `MembershipHandler` [5](#0-4) .

Because Shipit supports multiple GitHub Apps/organizations, each configured with its own `webhook_secret` [6](#0-5) , the org whose secret is checked (`repository.owner.login`) is never required to equal the org/repo that the handler actually acts on (`repository.full_name`, or `organization.login` for membership events).

### Finding Description
This is the same class of bug as the Party Governance rage-quit finding: a check is enforced on one field (the signature covers the raw byte string, so it does "cover" the whole body cryptographically), but the *authorization decision* — which organization is trusted — is derived from one field (`repository.owner.login`), while the *action performed* is keyed off a different field (`repository.full_name`, or `organization.login` in the membership case). The binding that should hold is:

`organization whose webhook_secret validated the request == organization/repository actually written by the handler`

This binding is never checked. An attacker who legitimately controls a GitHub organization/App installation of their own (`attacker-org`, with its own valid `webhook_secret` configured in Shipit for multi-org setups) can send a POST to `/webhooks` signed with `attacker-org`'s own secret, but with a JSON body whose `repository.owner.login` is set to `attacker-org` (so `verify_signature` picks and validates against `attacker-org`'s secret) while `repository.full_name` (or `organization.login`) references a completely different, unrelated repository/org tracked by the same Shipit instance. `verify_signature` only checks the HMAC against the secret for `attacker-org`; since the whole raw body (which the attacker controls, being the one crafting and sending it) is signed with a key the attacker legitimately possesses, `verify_webhook_signature` returns true [7](#0-6) . Handlers then act on the victim repository named in `repository.full_name`/`organization.login`, e.g.:
- `PushHandler#process` triggers `stack.sync_github` for stacks under the victim's repository [8](#0-7) .
- `StatusHandler#process` writes commit statuses on the victim's commits [9](#0-8) .
- `MembershipHandler#process` adds/removes arbitrary GitHub logins to/from a `Team` keyed by `organization.login`, which is the object gating `User#authorized?` and thus access to the whole Shipit UI (`Shipit.github_teams`) [10](#0-9) [11](#0-10) .

### Impact Explanation
This crosses the "organization authenticated versus repository/organization written" boundary explicitly called out in scope. In the worst case (`MembershipHandler`), an attacker can add an arbitrary GitHub login to a `Team` associated with `Shipit.github_teams`, which is the sole authorization gate in `User#authorized?` [11](#0-10)  and `force_github_authentication` [12](#0-11) , i.e. an authentication/authorization bypass into a Shipit instance without ever being a real member of that team on GitHub. Other handlers allow cross-repository writes (forged sync/status/check-run events) on stacks the attacker's own org has no relation to.

### Likelihood Explanation
This requires the operator to run Shipit in the documented multi-GitHub-App configuration (one webhook secret per organization) and for the attacker to control at least one of those configured organizations' Apps/secrets — a standard, documented deployment mode, not a misconfiguration outside the engine's own code. Given that, the exploit is a single crafted HTTP POST with no further privilege needed.

### Recommendation
In `WebhooksController#verify_signature`, after selecting the GitHub App by `repository_owner`, additionally assert that any repository/organization actually referenced deeper in the payload (`repository.full_name`'s owner segment, or `organization.login`) matches `repository_owner` before dispatching to handlers. Equivalently, have each `Handler` cross-check that the resolved `Repository`'s `owner` equals the verified `repository_owner` passed down from the controller, rejecting the event otherwise.

### Proof of Concept
1. Configure Shipit with two organizations in `config/secrets.yml`, e.g. `attacker-org` and `victim-org`, each with its own `webhook_secret` (a standard, documented multi-org setup) [6](#0-5) .
2. As the owner of `attacker-org`'s GitHub App, craft a `push` (or `membership`) webhook JSON body where `repository.owner.login` (or `organization.login` for the top-level org check) = `attacker-org`, but `repository.full_name` = `victim-org/victim-repo` (or, for membership, `organization.login` = `victim-org`).
3. Sign the raw body with `attacker-org`'s legitimately-known `webhook_secret` and POST it to `/webhooks` with header `X-Github-Event: push` (or `membership`).
4. `WebhooksController#verify_signature` computes `repository_owner = 'attacker-org'`, fetches `Shipit.github(organization: 'attacker-org')`, and `verify_webhook_signature` succeeds because the attacker signed with their own valid secret [13](#0-12) .
5. `PushHandler`/`MembershipHandler` then resolve and mutate `victim-org/victim-repo` state (or grant team membership gating authentication) based on `repository.full_name`/`organization.login`, which was never checked against the verified `attacker-org` [1](#0-0) .

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
