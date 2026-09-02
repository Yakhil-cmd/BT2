### Title
Webhook signature verification is keyed to `repository.owner.login`/`organization.login`, while the acted-upon target is keyed to `repository.full_name` — an org with no `webhook_secret` configured becomes a signature bypass for every other org's repositories - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` picks which `GitHubApp` (and therefore which `webhook_secret`) to validate a webhook against using `repository_owner`, a field read straight out of the attacker-supplied JSON body (`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`). The actual GitHub App instance's `verify_webhook_signature` treats a blank/unconfigured `webhook_secret` as automatically verified (`return true unless webhook_secret`). Meanwhile, every event handler picks the `Stack`/`Repository` to mutate using a *different* field from the same JSON body — `repository.full_name` — with no cross-check that this repository belongs to the organization that was actually used to verify the signature. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Finding Description
This mirrors the sherlock finding's bug class: a value being at its "empty/zero" state breaks a binding that the rest of the code silently assumes always holds. Here, the binding is: *the organization whose secret verified the signature == the organization that owns the repository being acted on*.

In a multi-org `config/secrets.yml` deployment (a documented, supported configuration — see `docs/setup.md` "Using Multiple Github Applications" and the example configs which explicitly allow `webhook_secret:` to be left blank/nil per org), each organization gets its own `GitHubApp` instance built from `@config[:webhook_secret].presence`. If any *one* configured organization has no `webhook_secret` set, `verify_webhook_signature` for that organization always returns `true`, regardless of the actual `X-Hub-Signature` header value: [5](#0-4) 

`WebhooksController#verify_signature` chooses which app/secret to check against purely from `repository.owner.login` in the untrusted body: [6](#0-5) 

Because that field lives in the same body whose fields are freely chosen by whoever is POSTing (there is no requirement that `repository.owner.login` matches `repository.full_name`'s owner segment), an attacker can craft a body where:
- `repository.owner.login` (or `organization.login`) = the name of an organization configured on this Shipit instance with no `webhook_secret` set → `verify_signature` passes unconditionally, with any or no `X-Hub-Signature` header.
- `repository.full_name` = `"victim-org/victim-repo"`, i.e. a completely different, properly-secured repository/stack.

The event handler that processes the request never re-checks the organization that was used for signature verification — it resolves the target purely from `repository.full_name`: [4](#0-3) 

So the payload field that is *acted on* (`repository.full_name`, used to locate the `Stack`/`Repository` to mutate) is never cross-validated against the field that the *verification step* trusted (`repository.owner.login`). The "signature" only proves the raw bytes weren't tampered with in transit for a chosen (attacker-selectable) organization context — it does not prove that context is the same one that will be acted upon.

### Impact Explanation
Depending on which webhook event/handler is invoked for `victim-org/victim-repo`, this allows an unauthenticated, unprivileged network attacker to forge writes such as:
- Triggering `GithubSyncJob` for push events on the target stack (out-of-band sync of arbitrary refs/SHAs).
- Creating/altering commit statuses, check-run/check-suite state, or PR label/merge-queue state via the `pull_request`/`status`/`check_suite` handlers, all keyed only by `repository.full_name`.

This is a cross-repository/cross-organization write achieved purely by exploiting the mismatch between the organization used to authenticate the webhook and the repository actually mutated — squarely in the "unauthorized deploy/rollback/merge" or "cross-repository writes" impact category, contingent on at least one configured organization lacking a `webhook_secret` (a state the codebase and its own documentation permit).

### Likelihood Explanation
The trigger condition — one organization in a multi-org config with `webhook_secret` blank — is explicitly shown as valid in the shipped example/test configs (`config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, `test/dummy/config/secrets.test.json`, `template.rb`), and `github_app.rb` was written to gracefully treat a missing secret as "no verification needed" rather than refusing to boot or refusing that path. Any operator running Shipit for several GitHub orgs, where one org's App hasn't had its webhook secret set yet (e.g. mid-setup, or an org where they didn't bother), unintentionally opens this cross-org bypass for all other stacks on the instance. No credentials, tokens, or repository access are required by the attacker — only knowledge that Shipit exposes `/webhooks` and the name of the loosely-configured org.

### Recommendation
- Require `webhook_secret` to be present for every configured organization; refuse to boot (or refuse to accept any webhook for that org) if it's blank, rather than treating blank secret as "always verified."
- Additionally/independently, after signature verification, assert that the organization that verified the signature (`repository_owner` derived at verification time) matches the owner segment of `repository.full_name` used by the handler before allowing any mutation — closing the gap even if a legitimate blank-secret org must be supported for local/dev use.

### Proof of Concept
1. Configure Shipit with two orgs: `victim-org` (has a real `webhook_secret`) and `throwaway-org` (leave `webhook_secret` blank, as shown acceptable in `config/secrets.development.example.yml`).
2. POST to `/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature` (or a garbage one), with body:
```json
{
  "repository": {
    "owner": { "login": "throwaway-org" },
    "full_name": "victim-org/victim-repo"
  },
  "after": "<attacker-chosen-sha>",
  "ref": "refs/heads/master"
}
```
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "throwaway-org")`, whose `verify_webhook_signature` returns `true` because `webhook_secret` is blank for that org — the request passes with `head(:ok)`/no 422.
4. `Shipit::Webhooks.for_event('push')` handler runs and resolves the target purely via `repository.full_name` ("victim-org/victim-repo"), enqueuing `GithubSyncJob` for the victim stack — a write performed without ever validating a signature meaningful to `victim-org`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
