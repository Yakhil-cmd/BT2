### Title
Webhook signature verification is bound to `repository.owner.login`, not to the `repository.full_name` the handlers act on, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature against using the attacker-controlled JSON field `repository.owner.login` (falling back to `organization.login`). The HMAC itself is only checked for validity against the raw body using that secret — it never verifies that `repository.owner.login` corresponds to the `repository.full_name` that the event handlers subsequently use to select which `Stack`/`Repository` records to act on. In a Shipit instance configured with multiple GitHub App organizations (as documented and supported by `Shipit.github_app_config`), a party who legitimately knows the `webhook_secret` for *their own* configured organization can forge a signature that is valid per `verify_signature`, while setting `repository.full_name` (and other repository fields) inside the same JSON payload to point at a completely different, victim organization's repository.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` picks a `GitHubApp` instance (and therefore its `webhook_secret`) keyed purely by this attacker-supplied string, using `github_app_config`: [2](#0-1) 

`GitHubApp#verify_webhook_signature` only checks the HMAC of the raw body against the secret picked above — it has no notion of which repository the payload claims to represent: [3](#0-2) 

Once the signature is "verified" for whichever organization `repository.owner.login` names, the full raw JSON (`params`) is dispatched unmodified to the event handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [4](#0-3) 

But the handlers resolve the target `Stack`/`Repository` using a *different* field of that same payload: `repository.full_name`, e.g. in the base `Handler` class:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

and `PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc. all independently re-derive the repository from `params.repository.full_name`: [6](#0-5) 

Nothing ties `repository.owner.login` (used for choosing the verifying secret) to `repository.full_name` (used for choosing which repository/stack is affected). Shipit explicitly supports and documents multi-organization configurations, where each org has its own independent `webhook_secret`: [7](#0-6) 

This is the same class of defect as the `twTAP`/`TapiocaOptionBroker` finding: a validity check is performed on one derived value (`pool.cumulative` / here, `repository.owner.login`) while the state actually mutated is a different value that the check does not constrain (the lock `magnitude` computed from user-controlled duration / here, `repository.full_name` used to select the target `Repository`/`Stack`). The equality that should hold — `organization whose secret authenticated the request == organization that owns the repository being acted upon` — is never enforced.

### Impact Explanation
Any actor who is a legitimate GitHub App administrator/webhook configurer for **any one** organization onboarded to a multi-org Shipit instance (i.e., they know that org's `webhook_secret`, which they themselves configured when installing the GitHub App for their own org) can forge webhook deliveries whose signature is valid under Shipit's check, but which reference an arbitrary victim `repository.full_name` belonging to a *different* onboarded organization. This lets them exercise webhook-driven actions against a repository/organization they have no privilege for, including:
- `push` events → `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for the victim's stacks, forcing GitHub sync activity and (for stacks with `continuous_deployment` enabled) can trigger continuous delivery for that branch based on forged `after` shas.
- `pull_request` `opened`/`closed`/`labeled`/`reopened` events → create, archive, or unarchive review stacks for the victim's repository.
- `membership` events → create/delete `Team`/`Membership`/`User` records tied to the victim org.
- `status`/`check_suite` events → inject forged commit statuses/check runs for the victim repository's commits, which feed into deploy-safety and merge-queue gating logic.

This crosses the credential/organization boundary the rules call out ("an organization that authenticated versus the repository that is written") and can result in unauthorized cross-repository writes and unauthorized deploy behavior — matching the report's High/Critical impact bar.

### Likelihood Explanation
Exploitability requires the attacker to be a party who legitimately administers the GitHub App installation (and therefore knows the `webhook_secret`) for at least one organization configured on a shared, multi-tenant Shipit instance that also hosts other organizations' repositories — this is exactly the deployment pattern documented in `docs/setup.md` under "Using Multiple Github Applications". The attacker does not need any Shipit session, API token, or access to the victim organization at all; they only need the ability to send a raw HTTP POST to the public `/github/webhooks` endpoint with a body they construct and sign themselves. This is a realistic operator/tenant-boundary crossing scenario for any Shipit deployment shared across multiple orgs.

### Recommendation
After computing `github_app` from `repository_owner`, additionally verify that the organization implied by `params.dig('repository', 'full_name')` (i.e., the substring before `/`) matches `repository_owner`/`organization.login` used for the secret lookup, rejecting the webhook (422) on mismatch. More robustly, resolve the target `Repository`/`Stack` in the same before_action that performs signature verification, and reject if the resolved repository's owning organization does not match the organization whose secret validated the signature — ensuring a single, consistent binding between "who authenticated" and "what is acted upon" throughout `create` and all `Shipit::Webhooks::Handlers`.

### Proof of Concept
Preconditions: Shipit instance configured with multiple orgs, e.g. `OrgOne` (attacker-administered) and `OrgTwo` (victim), per `test/dummy/config/secrets_double_github_app.yml`-style config, each with a distinct `webhook_secret`. `OrgTwo/victim-repo` has a Stack in Shipit.

1. Attacker knows `OrgOne`'s `webhook_secret` (they set it up themselves when installing their own GitHub App).
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgOne" },
    "full_name": "OrgTwo/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(OrgOne_webhook_secret, raw_body)`.
4. POST to `/github/webhooks` with header `X-Github-Event: push` and the signature above.
5. `verify_signature` calls `Shipit.github(organization: "OrgOne")`, verifies HMAC successfully (it matches, since attacker used the correct `OrgOne` secret) — request passes.
6. `create` dispatches `params` to `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name("OrgTwo/victim-repo")` — a repository the attacker has no authorization over — and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, forcing sync/deploy-adjacent behavior on the victim's stack despite the request never being authenticated for `OrgTwo`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
