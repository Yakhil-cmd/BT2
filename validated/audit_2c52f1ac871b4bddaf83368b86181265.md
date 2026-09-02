This confirms the multi-organization setup documented in `docs/setup.md:182-209`, where each GitHub organization gets its own independent `webhook_secret`, `app_id`, and `private_key`. This is the critical piece needed to validate the analog: the signature verification in `WebhooksController#verify_signature` binds trust to `repository_owner` (derived from `params.dig('repository', 'owner', 'login')`), but the actual write operations performed by handlers key off the independent `repository.full_name` field in the same payload.

### Title
Webhook signature verification keys off `repository.owner.login` while handlers act on the independent `repository.full_name` field, allowing cross-organization writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit deployment, each GitHub organization is configured with its own independent `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` selects which organization's `GitHubApp` (and thus which `webhook_secret`) to use for HMAC verification based solely on `repository_owner`, a value read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) [2](#0-1) . However, once the signature is accepted, `WebhooksController#create` dispatches the entire raw JSON payload to handlers [3](#0-2) , and every handler resolves the target `Repository`/`Stack` using a *different* field of that same payload: `payload.dig('repository', 'full_name')` [4](#0-3)  (and equivalently `params.repository.full_name` in the `pull_request/*` handlers, e.g. [5](#0-4) ).

### Finding Description
The equality that must hold, and that is not enforced, is:

`organization that authenticated the payload (repository.owner.login)` == `repository that is written by the handler (repository.full_name)`

Nothing in the JSON schema or in `ExplicitParameters` parsing ties `repository.owner.login` to the prefix of `repository.full_name`; they are two independently attacker-controlled string fields inside the same signed JSON blob. An attacker who legitimately controls a GitHub organization/repository that has the Shipit GitHub App installed (a normal, unprivileged setup step available to anyone who can install a GitHub App on their own org) knows or can trigger delivery of webhooks signed with *their own* organization's `webhook_secret`. Because `verify_webhook_signature` is a plain HMAC-SHA1 check over the raw body using the secret selected by `repository_owner` [6](#0-5) , the attacker can craft (or GitHub will deliver, and the attacker can control via their own installation settings) a payload where `repository.owner.login`/`organization.login` is their own org (so the correct, attacker-known secret is used and verification passes) while `repository.full_name` names a *different, victim* organization's repository that also happens to be onboarded in the same Shipit instance.

Once verification passes, every handler blindly trusts `repository.full_name` to look up the target `Stack`/`Repository` and mutate it: e.g. `push` events enqueue `GithubSyncJob` for the resolved stack, `pull_request` `opened`/`labeled`/`closed`/`reopened` handlers provision, archive, or unarchive review stacks belonging to the victim repository [7](#0-6) , and `membership` events can add/remove users from `Team`s tied to a different organization than the one that authenticated [8](#0-7) . This breaks the organization-authenticated vs. repository-written binding required by the security model, effectively letting one org's legitimately-configured GitHub App forge writes against another org's Shipit-managed repositories/stacks.

### Impact Explanation
This crosses a credential/repository trust boundary purely through a payload the attacker fully controls (their own org's webhook delivery), without any Shipit session, API token, or GitHub write access to the victim repository. Depending on which handler is reached, this can drive cross-repository/cross-organization writes: forcing syncs, provisioning/archiving review stacks, or manipulating team membership records for organizations the attacker does not control — matching the "cross-repository writes" / "unauthorized deploy/rollback" class of impact.

### Likelihood Explanation
Exploitability requires only that the Shipit instance be configured with the documented multi-organization `github:` schema and that the attacker controls (or can install the GitHub App on) at least one onboarded organization — a normal, low-privilege administrative action, not a compromise of the victim. No secrets belonging to the victim organization are needed.

### Recommendation
In `WebhooksController#verify_signature` / `#create`, and in `Handler#repository_name`, enforce that the organization used to select the webhook secret (`repository_owner`) matches the owner segment of `repository.full_name` before processing the event, rejecting the webhook (e.g., with 422) on mismatch.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret`, per the documented multi-org schema [1](#0-0) .
2. As the owner of `attacker-org`, install the Shipit GitHub App on a repo you control, and configure/trigger a webhook delivery (e.g. via the GitHub App's webhook redelivery/test feature, or a custom delivery endpoint you control that mirrors GitHub's signing) whose JSON body sets `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`, signed with `attacker-org`'s `webhook_secret`.
3. POST this payload to `/webhooks` with header `X-Github-Event: pull_request` (or `push`, `membership`).
4. Observe that `verify_signature` succeeds (using `attacker-org`'s secret) at `app/controllers/shipit/webhooks_controller.rb:24-49`, and the handler resolves and mutates the stack/repository belonging to `victim-org/victim-repo` via `Handler#repository_name` at `app/models/shipit/webhooks/handlers/handler.rb:36-38`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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
```
