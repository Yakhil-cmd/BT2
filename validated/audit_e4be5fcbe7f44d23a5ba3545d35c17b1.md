## Analysis

The bug class (a receiving/authorization value acted upon that isn't itself covered by the actual verification) maps onto `Shipit::WebhooksController#verify_signature`. The organization used to select which secret is checked comes from attacker-controlled payload data, but the rest of the payload (which is trusted afterward by handlers such as `MembershipHandler` and `StatusHandler`) is not bound to that same organization.

### Title
Webhook organization used for signature-secret lookup is attacker-controlled and decoupled from the payload actually processed - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization config (and thus which `webhook_secret`) to verify the signature against by reading `repository_owner`, itself taken directly from the untrusted JSON body. If any configured organization has no `webhook_secret` set, `GitHubApp#verify_webhook_signature` short-circuits to `true` for that organization regardless of the actual `X-Hub-Signature` header. An attacker can therefore pick that organization's login for `repository.owner.login`/`organization.login` to make the signature check pass unconditionally, while every other field in the same payload (repository full name, team id, sha, state, etc.) is processed unmodified by the event handlers for whatever target stack/team the attacker chooses.

### Finding Description
`repository_owner` is derived purely from the request body: [1](#0-0) 

That value selects the `GitHubApp` instance (and its `webhook_secret`) used to verify the HMAC signature: [2](#0-1) 

`verify_webhook_signature` trivially returns `true` when no secret is configured for that organization: [3](#0-2) 

Once `verify_signature` passes, the *entire* raw payload (not scoped to the organization used for verification) is dispatched to every registered handler for the event type: [4](#0-3) 

Handlers act on other payload fields that were never covered by the (bypassed) signature check, e.g. `MembershipHandler`, which creates/updates a `Team` and adds/removes members based on `params.team` / `params.member`, independent of the `organization.login` used only for signature lookup: [5](#0-4) 

and `StatusHandler`, which creates a commit status from attacker-supplied `sha`/`state`/`context` for any commit that matches, feeding directly into CI-gating logic used by `MergeRequest#all_status_checks_passed?` and deploy gating: [6](#0-5) 

This breaks the intended binding: **organization authenticated (secret verified) == repository/team/commit actually written**. The equality that should hold is `repository_owner used for HMAC verification == repository owner whose data is mutated`; instead, an attacker fully controls both sides independently within the same payload.

### Impact Explanation
If any tenant/org in the multi-org config (`secrets.github`) is configured without a `webhook_secret` (this is an explicitly supported, documented configuration — see `config/secrets.development.shopify.yml` showing `webhook_secret:` as nilable), an unauthenticated network attacker can:
- Forge `membership` events to add arbitrary GitHub users to arbitrary `Team` records used for `Shipit.github_teams` authorization checks (`User#authorized?`), directly escalating into the engine's team-based authorization gate — a High-severity outcome per the rules (`escalation into Shipit.github_teams authorization`).
- Forge `status` events to inject fabricated commit statuses for any known commit sha across any stack, undermining CI-gating relied on by `MergeRequest#all_status_checks_passed?`, contributing to unauthorized merges/deploys.
- Forge `push`/`check_suite` events causing sync jobs to run against stacks unrelated to the (weakly-configured) organization used only to pass the signature check.

### Likelihood Explanation
Exploitability depends entirely on the deployment having at least one configured GitHub organization/app with a blank `webhook_secret` — which the engine's own sample config (`config/secrets.development.shopify.yml`) treats as a normal/nilable value, and `GitHubApp#verify_webhook_signature` explicitly special-cases (`return true unless webhook_secret`). No credentials, sessions, or `ApiClient` tokens are required — only the ability to POST to the public `webhooks` endpoint, which is the intended entry point for GitHub. This is a configuration-dependent but code-level trust bypass, not a theoretical one.

### Recommendation
Do not let attacker-controlled payload content select which secret is used to validate that same payload. Either:
- Require every configured organization to have a non-blank `webhook_secret` (fail closed instead of `return true unless webhook_secret`), or
- Verify the signature against all configured secrets and only then re-derive/authorize which organization's data may be mutated, ensuring the verified organization strictly matches the organization whose resources (`repository.full_name`, `team`, `member`) are modified downstream.

### Proof of Concept
1. Configure two orgs in `secrets.github`: `org-a` (no `webhook_secret`) and `org-b` (`webhook_secret` set, and owns team `T` used for `Shipit.github_teams`).
2. POST to `/github/webhooks` with headers `X-Github-Event: membership` and no valid `X-Hub-Signature` (or an arbitrary one), and body:
   ```json
   {
     "action": "added",
     "team": { "id": 999, "name": "Owners", "slug": "owners", "url": "..." },
     "organization": { "login": "org-a" },
     "member": { "login": "attacker" }
   }
   ```
3. `repository_owner` resolves to `org-a`; `Shipit.github(organization: "org-a")` has a blank `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally.
4. `MembershipHandler#process` runs unchecked, creating/updating team `999` and adding `attacker` as a member — independent of the fact that `org-a`'s secret (or lack thereof) was what "authorized" the request.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
