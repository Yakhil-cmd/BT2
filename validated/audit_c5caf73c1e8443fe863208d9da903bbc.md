## Analysis

The `MembershipHandler` case is the clearest concrete example: `find_or_create_team!` sets `team.organization = params.organization.login` and grants/revokes membership based on `params.team.id` and `params.member.login` [1](#0-0) , while `PullRequest::ClosedHandler`/`PushHandler` resolve the target `Repository`/`Stack` purely from `payload.dig('repository', 'full_name')` [2](#0-1) [3](#0-2) . None of these fields is cross-checked against the field that was actually used to select the signing secret.

### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login` while state-mutating handlers act on the unrelated `repository.full_name`/`team`/`organization` fields of the same unverified payload - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App (and therefore which `webhook_secret`) to HMAC-verify the raw payload against using `repository_owner`, itself read straight out of the untrusted JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [4](#0-3) . `Shipit.github(organization: repository_owner)` resolves per-organization app configuration (multiple GitHub Apps/secrets are supported, as exercised in `test/unit/shipit_test.rb`) [5](#0-4) . Once the signature validates for *that* organization's secret, `create` dispatches the **entire unmodified payload** to every registered handler with no further binding to `repository_owner` [6](#0-5) .

Handlers, however, never consult `repository_owner`/`organization.login` to resolve *which* stack/team to mutate - they use a separate field of the same payload:
- `Handler#repository_name` (base class used by push/pull_request handlers) reads `payload.dig('repository', 'full_name')` [2](#0-1) .
- `PullRequest::ClosedHandler#repository` independently reads `params.repository.full_name` to look up `Shipit::Repository.from_github_repo_name` and then archives that repository's review stack [3](#0-2) .
- `MembershipHandler#process`/`#find_or_create_team!` creates/updates a `Team` keyed by `params.team.id` with `team.organization = params.organization.login`, and adds/removes the named `member` from it [1](#0-0) .

Because the HMAC only proves "this exact byte-for-byte body was signed with organization X's secret," and none of these three fields (`repository.full_name`, `team`/`member`, `organization.login` used by the handler) is required to equal the `repository_owner` value used to pick the secret, an attacker who legitimately controls one tenant's GitHub App webhook secret (org A, e.g. because they created/administer that GitHub App - a low-privilege action relative to any *other* tenant on the same Shipit install) can POST a payload where `repository.owner.login`/`organization.login` = "OrgA" (so the correct, valid secret is selected and the HMAC verifies) but `repository.full_name` = "OrgB/some-repo" (or `membership_handler`'s `team`/`member` fields reference OrgB's team/user). The signature check has no way to detect the mismatch because it verifies the *whole* forged body, including the mismatched fields, against OrgA's key.

### Finding Description
The trust boundary that should hold is:
`organization whose secret authenticated the request == organization/repository the handler mutates`

Before the attacker's forged request: this equality holds implicitly only because `repository.owner.login` and `repository.full_name`'s owner segment are expected to match in genuine GitHub-originated payloads.

After a forged request from an operator who holds org A's webhook secret: `repository_owner` (used for `verify_signature`) = "OrgA", but `repository.full_name`/`organization.login` consumed by the handler = "OrgB/...". The signature is valid (computed over OrgA's secret and the full raw body including the forged fields), yet the write target belongs to org B. This is structurally identical to the reported bug class: a control (signature/permission) is scoped to one entity while the actual effect touches a different, unauthorized entity - "an organization that authenticated versus the repository that is written."

Root cause is the split between:
- `app/controllers/shipit/webhooks_controller.rb:24-62` (`verify_signature`, `repository_owner`) - selects the trust anchor from the payload.
- `app/models/shipit/webhooks/handlers/handler.rb:32-38`, `pull_request/closed_handler.rb:49-53`, and `membership_handler.rb:22-43` - consume unrelated payload fields to decide what to mutate, with no cross-check against `repository_owner`.

### Impact Explanation
This allows cross-tenant/cross-repository writes on a multi-organization Shipit deployment: an attacker who only controls (or has stolen) one organization's low-value webhook secret can create/archive review stacks, trigger `GithubSyncJob`s, or add/remove arbitrary users from `Team`s (which gate `authorized?` and thus application access, see `Shipit::Authentication#force_github_authentication` and `User#authorized?`) belonging to a completely different organization/repository they do not control [7](#0-6) [8](#0-7) . Membership manipulation can escalate into unauthorized access to stacks (deploy/rollback capability), satisfying the "cross-repository writes" / "escalation into `Shipit.github_teams` authorization" impact bar.

### Likelihood Explanation
Requires the attacker to already control a valid `webhook_secret` for at least one organization configured on the same Shipit instance (multi-tenant setups are explicitly supported per `test/unit/shipit_test.rb`'s `secrets_double_github_app.yml` fixture). This is plausible for any Shipit install serving several orgs/teams where webhook secrets are managed at different trust levels, but does not apply to single-org deployments, and it does not require any Shipit-internal credential (`ApiClient` token, `github_access_token`, session, GitHub App private key) - only a raw webhook secret string, which is lower-privilege than the excluded categories.

### Recommendation
After signature verification, re-derive the organization from the resolved `Repository`/`Stack` (or from `repository.owner.login`) inside each handler and assert it equals the organization whose secret validated the request, rejecting the event otherwise. Alternatively, bind the verified organization into the payload object handlers receive so `Handler#repository_name`/`MembershipHandler#find_or_create_team!` cannot silently trust a different owner field.

### Proof of Concept
1. Attacker administers "OrgA" GitHub App on a Shipit instance that also hosts "OrgB" (per-org secrets, e.g. `config/secrets.yml` shaped like `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker crafts a `membership` event body:
   ```json
   {
     "action": "added",
     "team": { "id": 999, "name": "OrgB Admins", "slug": "orgb-admins", "url": "..." },
     "organization": { "login": "OrgB" },
     "member": { "login": "attacker-controlled-user" },
     "repository": { "owner": { "login": "OrgA" } }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: membership`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and verifies successfully against OrgA's secret [9](#0-8) .
5. `create` dispatches the full payload to `MembershipHandler`, which creates/updates a Team for `"OrgB"` and adds `attacker-controlled-user` as a member [1](#0-0) , granting them membership relevant to OrgB's `Shipit.github_teams` authorization despite the request only having been authenticated for OrgA.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** test/unit/shipit_test.rb (L11-22)
```ruby
    test ".github uses indifferent access to search through the Github applications" do
      secrets = ActiveSupport::OrderedOptions.new
      secrets.merge!(YAML.load_file('test/dummy/config/secrets_double_github_app.yml'))
      secrets.deep_symbolize_keys!
      Shipit.stubs(:secrets).returns(secrets)
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'OrgOne'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgOne))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'orgone'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :orgone))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgTwo))
      Shipit.unstub(:secrets)
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
