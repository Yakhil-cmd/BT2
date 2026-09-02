### Title
Webhook signature verification selects the signing organization from Rails' merged query+body params while the event payload processed by handlers is re-parsed from the raw request body, allowing a known-secret organization to forge events for a different, unrelated tracked organization/repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to validate the HMAC signature against by reading `repository_owner` off the standard Rails `params` object, which merges query-string parameters over the JSON body. The actual event payload dispatched to handlers in `#create` is independently re-parsed straight from `request.raw_post`. Because the HMAC only certifies the raw body bytes and never the org-selection key, an attacker who knows the `webhook_secret` for any one organization configured in a multi-organization Shipit deployment can sign an arbitrary raw body describing an event for a *different* organization/repository, then force the org used for signature lookup (via the query string) back to the organization whose secret they know. Verification succeeds against the known secret while the handlers act on the forged payload targeting the unrelated repository/stack.

### Finding Description
`Shipit.github` supports a multi-organization config schema where each org key under `secrets.github` carries its own independent `webhook_secret`: [1](#0-0) 

The controller derives which org's secret to check against from `params`, not from the raw signed body: [2](#0-1) [3](#0-2) 

`repository_owner` calls `params.dig('repository', 'owner', 'login')`. Rails' `params` is the merge of query-string parameters and parsed-body parameters, and in `ActionDispatch::Http::Parameters#parameters` the query-string values take precedence over body values for colliding keys (`request_parameters.merge(query_parameters)`). This means an attacker can append `?repository[owner][login]=<org-they-know-the-secret-for>` to the webhook URL and force `verify_signature` to fetch and check against a secret of their choosing, entirely independent of what the signed raw body actually contains.

Meanwhile, the event actually acted upon is taken from a **fresh, independent** re-parse of the raw body, ignoring the query-string-poisoned `params`: [4](#0-3) 

So the binding that should hold — "the organization whose secret authenticated this request" == "the organization/repository the dispatched handlers act on" — is broken. `verify_signature` authenticates organization *A* (selected via the unsigned query string) while `create`'s handlers write against whatever organization/repository is embedded in the signed raw body, which the attacker fully controls as long as they can produce a valid HMAC for it using *A*'s secret (which they know, e.g. because they administer their own org's webhook integration on the same shared Shipit instance).

### Impact Explanation
This is a cross-organization/cross-repository forgery. An external actor who legitimately possesses the `webhook_secret` for one tracked GitHub organization (e.g., their own onboarded org in a multi-tenant Shipit deployment) can forge signed webhook deliveries (`push`, `status`, `check_suite`, `membership`, etc.) that are processed as if they originated from a completely different organization's repository whose secret they do not know. Depending on which webhook handlers are registered, this can drive fabricated commit statuses, fabricated `check_suite` completions that trigger `RefreshCheckRunsJob`, or team/user membership mutations for a repository/org outside the attacker's control — enabling unauthorized manipulation of deploy-affecting state (e.g., CI status used as a deploy gate) for a stack the attacker has no legitimate access to. This matches the "cross-repository writes" / unauthorized deploy-gating impact category.

### Likelihood Explanation
Exploitability requires only: (1) the Shipit instance is configured with the multi-organization `github` schema (a supported, documented configuration), and (2) the attacker legitimately knows the `webhook_secret` of at least one organization tracked by that instance (trivial if they are themselves an onboarded org admin who configured their own GitHub App/webhook secret). No Shipit session, API token, or GitHub write access is required — only the ability to send an arbitrary HTTP POST to the public webhooks endpoint with a custom query string, which is always attacker-controlled since the endpoint is unauthenticated by design (webhook endpoints must be internet-reachable).

### Recommendation
Derive the organization used for signature verification from the same trusted, signed source that handlers use to process the event — i.e., parse `request.raw_post` once (as `#create` does) and use that parsed body exclusively for both organization selection and dispatch, never falling back to the mutable, unsigned `ActionController::Parameters` (`params`) which can be influenced by the query string. Alternatively/additionally, verify the signature against every configured organization's secret (or bind the endpoint per-organization via routing) rather than trusting an unauthenticated field to pick the verification key.

### Proof of Concept
1. Shipit is configured with two organizations, `victim-org` (private, high-value stacks) and `attacker-org` (attacker legitimately administers this org's GitHub App/webhook and thus knows `attacker-org`'s `webhook_secret`).
2. Attacker crafts a JSON body describing, e.g., a `check_suite` "completed"/"success" event whose `repository.owner.login` / `repository.full_name` reference `victim-org/private-repo` and a commit SHA the attacker wants marked as passing.
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` over that exact raw body using `attacker-org`'s known `webhook_secret`.
4. Attacker POSTs the body to `.../github/webhooks?repository[owner][login]=attacker-org` with header `X-Github-Event: check_suite`.
5. `verify_signature` computes `repository_owner` from `params` (which now resolves to `attacker-org` due to the query string override), calls `Shipit.github(organization: 'attacker-org')`, and validates the signature against `attacker-org`'s secret — which matches, so `verified` is `true`.
6. `create` re-parses `request.raw_post` (unaffected by the query string) and dispatches the handler for `check_suite` using the body's real `victim-org/private-repo` data, causing `RefreshCheckRunsJob` (or equivalent handler logic) to run against the victim's stack/commit as though GitHub itself sent it.

### Citations

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
