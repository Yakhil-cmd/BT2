### Title
Webhook signature verification selects the GitHub App/secret by `repository.owner.login`, but every event handler resolves the target repository by the unrelated `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which `GitHubApp` (and thus which `webhook_secret`) to validate the request against using `repository_owner`, computed from `params.dig('repository','owner','login')` (or `organization.login`). Once the signature check passes, `create` dispatches the *entire raw payload* to all registered handlers. Each handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) independently determines the target `Stack`/`Repository` using `payload.dig('repository', 'full_name')` via `Handler#repository_name`. These two payload fields are never cross-checked against each other.

### Finding Description
`Shipit.github(organization: repository_owner)` is looked up purely to find the secret to validate the signature: [1](#0-0) . This method looks up per-organization configuration and, critically, `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever that organization's `webhook_secret` is blank: [2](#0-1) . Shipit explicitly supports (and documents) running with several GitHub organizations, each with its own, independently-configured `webhook_secret`, some of which may be left blank/`nil`: [3](#0-2) , [4](#0-3) .

After (or regardless of) the outcome of `verify_signature`, `create` still parses the raw body and always invokes the matching handlers with the full, attacker-controlled JSON: [5](#0-4) . Handlers do not use `repository_owner`/`organization.login` at all; they resolve their target `Stack` purely via `payload.dig('repository', 'full_name')`: [6](#0-5) . For example `PushHandler#process` calls `stack.sync_github(...)` for whatever stacks match that `full_name`: [7](#0-6) , and `StatusHandler#process` creates a commit status (used as a CI signal for deploy gating) for whatever commit SHA is supplied, entirely independent of which org's secret validated the request: [8](#0-7) .

The binding that should hold is: `organization authenticated by signature == organization owning the repository the handler mutates`. In this implementation that equality is never enforced — `repository.owner.login` (checked) and `repository.full_name` (acted upon) are two independently attacker-supplied JSON fields inside the same unsigned-or-weakly-signed payload.

### Impact Explanation
An unprivileged, unauthenticated external attacker who can reach the `/webhooks` endpoint can:
1. Set `repository.owner.login` (or `organization.login`) to any GitHub organization configured in this Shipit instance whose `webhook_secret` is blank (a documented, legitimate configuration option), causing `verify_signature` to accept the request with no valid signature at all.
2. Set `repository.full_name` inside the same payload to point at a completely different, "secured" organization's repository that Shipit tracks.
3. Have the dispatched handler act on that unrelated repository's `Stack` — e.g. `PushHandler` calling `stack.sync_github`, or `StatusHandler` writing an attacker-chosen commit status (`state`, `context`) for an arbitrary SHA in that stack.

Because commit statuses are used by Shipit to gate deployability and continuous delivery, an attacker can inject a fabricated "green" CI status for a commit in a stack they do not own, enabling deploy-gating bypass and potentially triggering an unauthorized deploy through continuous delivery — this qualifies as a Critical "unauthorized deploy" per the impact criteria. At minimum, this also enables unauthenticated writes to arbitrary tracked repositories' state (`sync_github`, team/membership mutation via `MembershipHandler`), which qualifies as High "unauthenticated... task streams" / cross-repository writes even without the deploy-gating angle. The severity scales with the number of organizations configured on the instance and whether any of them has an unset `webhook_secret` — a state explicitly supported and documented by the engine, not a misconfiguration outside its documented deployment model.

### Likelihood Explanation
This requires only that the Shipit instance is configured for multiple GitHub organizations (a documented, supported feature) and that at least one of those organizations has no `webhook_secret` set (also an explicitly documented, optional field, shown as the default in the example secrets files). No credentials, tokens, or GitHub App private keys are required by the attacker — only knowledge that the target Shipit instance tracks a specific organization's repositories, which is discoverable from the public UI/stack list. This is a design flaw in the trust binding between signature validation and payload dispatch, not a theoretical or best-practice concern.

### Recommendation
Enforce that the organization used to select/verify the webhook signature is the *same* organization owning the repository/entity that handlers subsequently act upon. Concretely:
- Reject payloads where `repository.owner.login` (or `organization.login`) does not match the owner embedded in `repository.full_name`.
- Pass the already-verified `repository_owner` into each handler and have `Handler#stacks`/`#repository_name` cross-validate against it instead of trusting `full_name` alone.
- Consider always requiring a non-blank `webhook_secret` for every configured organization, refusing to boot/serve webhooks for organizations with no secret configured.

### Proof of Concept
Preconditions: Shipit configured with multiple GitHub organizations (per `docs/setup.md` "Using Multiple Github Applications"), where organization `no-secret-org` has `webhook_secret: nil` and organization `victim-org` (which Shipit also tracks, e.g. stack `victim-org/critical-app`) has a real secret configured.

```
POST /webhooks
X-Github-Event: status
(no valid X-Hub-Signature required)

{
  "repository": {
    "owner": { "login": "no-secret-org" },
    "full_name": "victim-org/critical-app"
  },
  "sha": "<any sha tracked for victim-org/critical-app>",
  "state": "success",
  "context": "<required CI context configured for that stack>"
}
```

- `verify_signature` computes `repository_owner = "no-secret-org"`, calls `Shipit.github(organization: "no-secret-org")`, and `verify_webhook_signature` returns `true` unconditionally because that org's `webhook_secret` is blank.
- `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which looks up the commit purely by `params.sha` (no organization scoping) and creates a forged "success" status, independent of the fact that the signature check was performed against an unrelated organization. [9](#0-8) [2](#0-1) [6](#0-5) [8](#0-7)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
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
