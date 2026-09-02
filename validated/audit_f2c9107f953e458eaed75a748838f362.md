### Title
Webhook signature verification is bound to `repository.owner.login`, but event handlers act on the independently-attacker-controlled `repository.full_name` field, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate an inbound webhook against solely based on `repository.owner.login` (or `organization.login`) taken from the *unauthenticated* JSON body, while the downstream event handlers (push, status, check_suite, pull_request, etc.) resolve the target `Stack`/`Repository` using `repository.full_name`, a separate field in that same unauthenticated body. Because the signature only proves the request was signed with the secret belonging to the organization named in `owner.login`, and nothing ties `owner.login` to `full_name`, an attacker who controls (or is a collaborator/webhook-capable member of) any one GitHub organization configured in Shipit can forge a validly-signed webhook whose `owner.login` matches their own org (so the HMAC check passes with a secret they know) while `full_name` names a **different**, victim repository/stack that they do not control.

### Finding Description
`Shipit::WebhooksController` picks the verification key like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the untrusted request body (`params.dig('repository', 'owner', 'login')`). `Shipit.github(organization: repository_owner)` then looks up the `GitHubApp` config (and its `webhook_secret`) for that org name via `github_app_config`: [3](#0-2) 

This is a legitimate multi-organization feature (`docs/setup.md` documents configuring one `webhook_secret`/app per GitHub org), confirmed by the double-app fixture: [4](#0-3) 

The HMAC comparison itself is only against the secret for that one selected org: [5](#0-4) 

Once `verify_signature` passes, `create` blindly re-parses the same raw body and dispatches it to every handler registered for the event type: [6](#0-5) 

Handlers resolve the affected `Stack` via `Repository.from_github_repo_name`, which parses `owner/name` out of a repo-name string built from the payload's `repository.full_name` (a field independent from `repository.owner.login`): [7](#0-6) 

No code anywhere cross-checks that `owner.login` (the field used to select the signing secret) equals the owner segment of `full_name` (the field used to select which Stack/Repository gets mutated). This breaks the intended binding: **organization that authenticated == repository that is written**. Instead the actual invariant enforced is just "some org's secret matched something in the body," and the "something" used for the actual state mutation is a completely different, unauthenticated field.

An attacker who has push/webhook-triggering access to *any* GitHub organization/repo that is configured as one of Shipit's `github:` orgs (e.g., they are a contributor on a low-trust org onboarded to the same Shipit instance, or they can trigger a `ping`-style event by any means that lets them control the raw payload GitHub signs, such as a repository they administer under that org) can get GitHub to sign a payload for their own org, then modify (or, if they can fully control the payload contents that GitHub will sign — e.g. via a custom/legacy webhook they set up for their own repo under that org, or by directly sending a self-crafted payload if `webhook_secret` for that org is otherwise obtainable) `repository.full_name` to point to `victim-org/victim-repo`. Handlers like the push handler will then queue jobs (`GithubSyncJob`), create commit `Status` rows, resolve pull-request/review-stack state, etc. against the victim's `Stack`, none of which actually originated from the victim organization's GitHub App/webhooks.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" boundary called out in scope. Concretely it allows an attacker with control of one onboarded low-privilege GitHub org's webhook traffic to inject fabricated `push`, `status`, `check_suite`, or `pull_request` events that are processed as if they came from a different, victim repository/stack tracked by the same Shipit instance — e.g. forging green CI `status` events to make an undeployed/unsafe commit `deployable?`, or triggering `GithubSyncJob`/`RefreshCheckRunsJob` state changes and continuous-deployment triggers for a stack the attacker has no legitimate access to. This can lead to an unauthorized deploy being triggered on the victim stack (continuous deployment reacts to forged `status`/`check_suite` webhooks), which matches the Critical "unauthorized deploy" impact category.

### Likelihood Explanation
Requires the Shipit instance to be configured with the multi-organization `github:` schema (explicitly documented/supported) and the attacker to control (or otherwise cause GitHub to sign a payload for) at least one of the onboarded organizations while a victim stack from a different org exists on the same instance. This is a realistic configuration for larger deployments that onboard many teams/orgs onto one shared Shipit instance, matching the documented "Using Multiple Github Applications" feature.

### Recommendation
In `WebhooksController`, after selecting the `GitHubApp` by `repository_owner` and verifying the signature, additionally verify that the owner segment of `repository.full_name` (and/or `organization.login`) equals `repository_owner` before dispatching to handlers; reject (422) on mismatch. More robustly, resolve the target `Stack`/`Repository` and enforce that its `repository.owner` matches the same org whose secret validated the signature, rather than trusting `full_name` unconditionally in handler code.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `attacker-org` and `victim-org`, each with its own `webhook_secret` (multi-org schema, as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker controls a repo under `attacker-org` and knows/derives `attacker-org`'s webhook secret path (e.g. by triggering their own legitimate webhook and capturing signed traffic, or, if they administer the GitHub App installation for `attacker-org`, by knowing its `webhook_secret` outright).
3. Attacker crafts (or replays/edits) a `push`/`status` JSON body where:
   - `repository.owner.login = "attacker-org"` (drives `verify_signature`'s org lookup, so the secret used to compute `X-Hub-Signature` is `attacker-org`'s known secret),
   - `repository.full_name = "victim-org/victim-repo"` (drives the actual `Stack`/`Repository` lookup in the event handler via `Repository.from_github_repo_name`).
4. Attacker computes a valid `X-Hub-Signature` using `attacker-org`'s webhook secret over this crafted body and POSTs it to `/github/webhooks` (or configured webhook path).
5. `verify_signature` passes because the signature matches `attacker-org`'s secret. `Shipit::Webhooks.for_event('push'/'status').each { |handler| handler.call(params) }` executes handlers against `victim-org/victim-repo`'s `Stack`, mutating its state (e.g., enqueuing `GithubSyncJob`, creating a fabricated commit `Status`, or triggering continuous deployment) despite the request never having been signed by `victim-org`'s actual GitHub App.

### Citations

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-6)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
