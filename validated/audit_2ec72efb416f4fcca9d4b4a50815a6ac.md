Found the binding-break: `WebhooksController#verify_signature` selects the GitHub App (and thus the HMAC secret) using the payload's `repository.owner.login` (falling back to `organization.login`), while every event `Handler` (`Handlers::Handler#stacks` / `#repository_name`) subsequently resolves the target `Repository`/`Stack` using `repository.full_name` — a *different* field of the same signed payload that is never itself checked against the field used to pick the verification key.

### Title
Webhook organization used for signature-key selection is decoupled from the repository acted upon by event handlers - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App config (and therefore which HMAC secret) to verify the `X-Hub-Signature` against solely from `repository.owner.login` (or `organization.login` as fallback). [1](#0-0) 
Once the signature check passes, the event is dispatched to a `Handlers::Handler`, which independently derives the acted-upon repository from `repository.full_name` in the same payload, with no re-validation that this repository belongs to the organization whose secret was used to authenticate the request. [2](#0-1) 

### Finding Description
In a multi-organization Shipit deployment, `Shipit.github(organization:)` maps an organization login to a distinct GitHub App / webhook secret configuration. [3](#0-2) 
`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and uses that value only to select which of these per-organization secrets to HMAC-verify the raw body against. [4](#0-3) 
The HMAC check (`verify_webhook_signature`) proves only that *some* secret configured for that specific `repository_owner` produced the signature — it says nothing about which `repository.full_name` the payload claims events happened on. [5](#0-4) 
Downstream, `Handlers::Handler#repository_name` / `#stacks` re-reads `repository.full_name` from the very same trusted payload to look up the `Repository` and its `Stack`s and act on them (e.g. `push`, `check_suite`, `status`, `membership`, `pull_request` handlers). [6](#0-5) 
Nothing enforces `repository.full_name`'s owner segment equals the `repository_owner` value that selected the verifying secret. If an attacker's own GitHub organization is genuinely installed in Shipit (has its own legitimate `webhook_secret`), they can send a webhook whose `repository.owner.login` is their own org (so the signature check passes with their own secret) but whose `repository.full_name` names a different repository/stack belonging to another organization tracked by the same Shipit instance. The equality that should hold — `organization that authenticated == repository that is written` — is broken because the signature only binds the organization field, not the repository-acted-upon field.

### Impact Explanation
Handlers act on stacks resolved purely from `repository.full_name`: e.g. `push_handler.rb`, `status_handler.rb`, `check_suite_handler.rb`, and `membership_handler.rb` create/modify `Commit`, `CheckRun`, `Team`, and `User` records and can trigger `RefreshCheckRunsJob` / continuous-delivery-relevant state for a stack the attacker's org does not own, effectively allowing cross-organization writes into another team's Shipit stack state (commit statuses, check runs, membership/team records) despite passing signature verification with the attacker's own credentials.

### Likelihood Explanation
Requires the Shipit instance to be configured with multiple GitHub organizations sharing one installation (`docs/setup.md`'s "Using Multiple Github Applications" mode), and requires the attacker to control (or be a legitimate member of) one of the configured organizations to obtain a validly-signed webhook. This is a realistic, documented, supported configuration, not a hypothetical one.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handlers::Handler`), validate that `repository.full_name`'s owner matches the organization/repository_owner whose secret validated the signature before dispatching to handlers; reject events where these two fields disagree.

### Proof of Concept
1. Configure Shipit with two orgs, `AttackerOrg` and `VictimOrg`, each with their own `webhook_secret` (multi-org mode per `docs/setup.md`).
2. As a member of `AttackerOrg`, craft a JSON payload with `organization.login`/`repository.owner.login` = `AttackerOrg`, but `repository.full_name` = `VictimOrg/some-victim-repo`.
3. Sign the raw body with `AttackerOrg`'s legitimate `webhook_secret` and send it as `X-Hub-Signature`.
4. `verify_signature` resolves `repository_owner` = `AttackerOrg`, fetches `AttackerOrg`'s app, and the HMAC check passes.
5. The dispatched handler (e.g. `status_handler.rb`) resolves the target repository/stack from `repository.full_name` = `VictimOrg/some-victim-repo`, updating commit status / check-run state on `VictimOrg`'s stack despite the attacker never authenticating as `VictimOrg`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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
