### Title
Webhook organization-selection uses Rails' merged `params` (query-string overridable) while signature verification and payload processing use the raw request body, letting an attacker with a *valid webhook secret for any configured GitHub organization* forge events for a *different* organization's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which per-organization webhook secret to validate against by calling `repository_owner`, which reads from the framework's merged `params` object (`params.dig('repository','owner','login')`) rather than from the exact bytes that were HMAC-signed (`request.raw_post`). [1](#0-0) 
Rails builds `params` as `request_parameters.merge(query_parameters)` (body parsed from JSON, then overwritten by query-string values for identical top-level keys), so an attacker can supply a `?repository[owner][login]=<their-org>` query parameter that silently replaces the `repository` key used only for **organization selection**, while the actual event body (`JSON.parse(request.raw_post)`) — used to select which repository's stacks are updated — is untouched. [2](#0-1) 

Because `Shipit.github(organization:)` looks the organization up in `secrets.github` and raises only for a *completely unknown* organization, an attacker who has (or is given) a webhook secret for **any** organization configured on the same multi-tenant Shipit instance can compute a valid `X-Hub-Signature` for that organization, then submit a body whose `repository`/`ref`/`sha`/`state` fields target a *different* organization's stack. The equality the design relies on is:

`organization authenticated by verify_signature == organization whose repository is written by create/handler`

The query-parameter override breaks this equality: the left side is attacker-selectable via the query string, the right side is fixed by the raw JSON body.

### Finding Description
- Signature verification: `verify_signature` resolves `github_app = Shipit.github(organization: repository_owner)` and then checks the signature against `request.raw_post` using that org's `webhook_secret`. [3](#0-2) 
- `repository_owner` is derived from `params`, not from `request.raw_post`: [4](#0-3) 
- The actual work is dispatched from a **separately re-parsed** JSON body: `params = JSON.parse(request.raw_post); Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [2](#0-1) 
- Handlers derive the target repository/stacks purely from this body, e.g. `Handler#repository_name` (`payload.dig('repository','full_name')`) and `PushHandler#process` (syncs stacks matching `branch`/`params.after`), `StatusHandler#process` (creates a commit status from `params.sha`/`params.state`). [5](#0-4) [6](#0-5) [7](#0-6) 
- The per-organization signature model is enforced in `GitHubApp#verify_webhook_signature`, keyed off `@webhook_secret` set per organization config, and `Shipit.github`/`github_app_config` select the config purely from the `organization` string passed in — no cross-check that this string matches the body's actual repository owner. [8](#0-7) [9](#0-8) 

This is directly analogous to the reported bug class: a value used for a security decision (`floatingRate`/here, `repository_owner` selecting the trusted signer) is not the same value that the downstream logic actually consumes and bounds (the time-weighted `floatingIndex`/here, the real body's `repository`), because Rails' merged `params` (query-overridable) is conflated with the byte-exact signed payload.

### Impact Explanation
This breaks the deployment-trust binding "organization that authenticated versus the repository that is written." On a multi-org Shipit deployment (`secrets.github` configured with multiple organization keys, each with its own `webhook_secret`), an actor who legitimately controls or knows the webhook secret for *one* onboarded organization can forge `push`, `status`, `check_suite`, or `deployable_status` events that are accepted as validly signed but whose body content targets a stack belonging to a *different* organization on the same instance. Depending on the forged event this enables:
- Forged `push` events triggering `GithubSyncJob`/`sync_github` against an arbitrary stack (`PushHandler#process`), influencing what Shipit believes is the HEAD to deploy. [6](#0-5) 
- Forged `status` events injecting a fabricated "success" CI status for a target commit sha (`StatusHandler#process`), which can satisfy `ci.require` gating and enable continuous delivery to auto-deploy that commit with the real `GITHUB_TOKEN`. [7](#0-6) 

This falls under the Critical bucket ("an unauthorized deploy, rollback or merge") because it can be used to make a commit appear deployable and trigger an actual deploy against a repository the attacker does not control, bypassing the intended per-organization webhook trust boundary.

### Likelihood Explanation
Exploitability requires the deployment to use the multi-organization `secrets.github` schema (multiple orgs each with their own `webhook_secret`) — a supported and documented configuration — and requires the attacker to hold a valid webhook secret for at least one org on that instance (e.g., their own onboarded org, or one leaked/rotated-but-still-accepted secret). No GitHub App private key, `api_clients_secret`, Shipit session, or repository write access is needed; the attacker only needs the ability to send an HTTP POST to `/webhooks` with a crafted query string and a validly-signed-for-their-org body content that logically targets a different org's repository name/branch/sha. This is a moderate-likelihood, config-dependent issue: it is not exploitable on single-organization Shipit installs (where `Shipit.github(organization:)` ignores the passed organization entirely, per `github_default_organization.nil?` in `lib/shipit.rb`), but is directly exploitable on any multi-tenant deployment. [10](#0-9) 

### Recommendation
- Do not use the framework-merged `params` (query+body) to make any trust decision in `verify_signature`. Derive `repository_owner` from the same parsed JSON body object that is later dispatched to handlers (`JSON.parse(request.raw_post)`), computed once and reused, instead of via the implicit `params` accessor.
- Alternatively/additionally, after selecting the organization and verifying the signature, re-derive the repository owner from the actual dispatched payload and assert it matches the organization whose secret validated the signature; reject (422) on mismatch.
- Consider disabling/blocking Rails' query-string parameter merging on the webhooks route entirely (e.g., only read `request.raw_post`, never `params`, in this controller) since this endpoint should be driven exclusively by the signed body.

### Proof of Concept
Preconditions: Shipit configured with `secrets.github` containing at least two organizations, `attacker-org` (secret known to the attacker, e.g. their own onboarded org) and `victim-org` (target).

1. Attacker computes `sig = HMAC-SHA1(attacker-org's webhook_secret, body)` for a JSON body:
```json
{"ref":"refs/heads/main","after":"deadbeefcafebabe...","repository":{"full_name":"victim-org/victim-repo","owner":{"login":"victim-org"}}}
```
2. Attacker POSTs:
```
POST /webhooks?repository[owner][login]=attacker-org HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=<sig>
Content-Type: application/json

{"ref":"refs/heads/main","after":"deadbeefcafebabe...","repository":{"full_name":"victim-org/victim-repo","owner":{"login":"victim-org"}}}
```
3. In `verify_signature`, `repository_owner` resolves to `"attacker-org"` (query-string wins over the body's `repository` key in Rails' merged `params`), so `Shipit.github(organization: 'attacker-org')` is used and the signature validates successfully with the attacker's own known secret. [1](#0-0) 
4. `create` then re-parses `request.raw_post` (unaffected by the query string) and dispatches the `push` handler with `repository.full_name == "victim-org/victim-repo"`, causing `PushHandler#process` to sync stacks under `victim-org/victim-repo` as if GitHub itself had sent the event. [2](#0-1) [6](#0-5) 

Note: I could not execute this against a live Rails instance to empirically confirm the exact precedence of `request_parameters.merge(query_parameters)` in the specific Rails/Rack version vendored by this engine (this is standard Rails `ActionDispatch::Http::Parameters` behavior, but the exact gem version's Rack parameter parsing was not directly inspectable via the indexed files). This should be empirically verified in a running instance before treating the severity as fully confirmed.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
