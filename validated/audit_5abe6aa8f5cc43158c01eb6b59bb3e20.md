This confirms the mechanism completely. The behavior described in the question is real: `Shipit.github(organization: repository_owner)` raises `Shipit::GithubOrganizationUnknown` only when the org key is absent from `secrets.github`, causing a `head(422)` in the `rescue` clause of `WebhooksController#verify_signature`. For a configured org whose `webhook_secret` is nil, `GitHubApp#verify_webhook_signature` short-circuits with `return true unless webhook_secret`, so `verified` is `true`, no `head(422)` is called, and the request falls through to `create`, which processes the forged payload and returns `head(:ok)`.### Title
Webhook signature bypass for orgs configured without `webhook_secret`, detectable via 422 vs 200 response codes - (File: `lib/shipit/github_app.rb`, `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` distinguishes a truly-unregistered organization (`GithubOrganizationUnknown` → `head(422)`) from a registered-but-secretless organization, for which `GitHubApp#verify_webhook_signature` unconditionally returns `true` and the request proceeds to `head(:ok)`. This response-code divergence lets an unauthenticated caller enumerate which configured organizations lack a `webhook_secret`, and for exactly those organizations any payload with an arbitrary (or absent) `X-Hub-Signature` is accepted and dispatched to the real event handlers.

### Finding Description
Binding under test: `verify_webhook_signature(signature, payload) == true` should require a valid HMAC over `payload` using a real `webhook_secret`, for every organization present in `secrets.github`. The actual code breaks this equality: [1](#0-0) 

`return true unless webhook_secret` means that whenever `@config[:webhook_secret]` is blank for an org entry that does exist in `secrets.github`, verification is vacuously true regardless of the signature header content.

In the controller, the split between "org missing" and "org present" is explicit: [2](#0-1) 

- `Shipit.github(organization: repository_owner)` raises `GithubOrganizationUnknown` only when the org key is entirely absent from `secrets.github` (`lib/shipit.rb:170-181`), producing `head(422)` in the `rescue`.
- For any org key that is present, `GitHubApp.new` is returned even if `webhook_secret` is nil (`lib/shipit/github_app.rb:44-57`), and `verify_webhook_signature` returns `true`, so no `head(422)` is issued in the main body and the filter chain continues into `create`, which dispatches to `Shipit::Webhooks.for_event(event)` handlers and finally returns `head(:ok)`.

Attacker flow:
1. Send `POST /webhooks` with `X-Github-Event: push` and `repository.owner.login` set to a guessed org name, any signature header. Observe 422 (unknown org, per existing test `test/controllers/webhooks_controller_test.rb:109-127`) vs 200/ok (org exists, secret unset or bypass hit).
2. For an org that returned 200/ok, craft a full push/status payload naming that org's real `repository.full_name`, with a bogus/absent `X-Hub-Signature`. `PushHandler`/`StatusHandler` (`app/models/shipit/webhooks/handlers/push_handler.rb`, `.../status_handler.rb`) run unauthenticated against that repository's real `Stack`/`Commit` rows — no session, API token, or GitHub secret is presented anywhere in this path.

Existing guards that fail to stop this: `verify_signature`'s only real check is `verify_webhook_signature`, which is neutered by the `unless webhook_secret` short-circuit; `drop_unhandled_event` only filters unrecognized event types, not signatures; there is no `require_permission!`/`User#authorized?`/`force_github_authentication` involved anywhere in `WebhooksController`, which is a public unauthenticated endpoint by design (webhooks). `check_if_ping` and `ExplicitParameters` schemas are irrelevant to signature enforcement.

### Impact Explanation
Any organization entry in `secrets.github` that is configured without a `webhook_secret` (a state the app itself documents as a valid config shape, e.g. `config/secrets.development.example.yml:11` and the multi-org example in `docs/setup.md:182-209`, both showing `webhook_secret:` with no value) accepts fully forged webhook payloads for its repositories. This is authentication bypass on the webhook ingress: an attacker can drive `PushHandler`/`StatusHandler` (and other registered handlers) to mutate `Repository`, `Stack`, and `Commit` rows for any repository under that organization, without holding any Shipit or GitHub credential. The information leak (422 vs 200) simply lets the attacker efficiently discover which orgs are exploitable this way, but the exploit itself doesn't strictly require the leak — an attacker who already knows (or guesses) an org name configured without a secret can go straight to step 2. Severity: Critical, per the rubric's "authentication bypass (forged webhook accepted)" and "a payload for one repository mutating another's stack, commit... row" criteria.

### Likelihood Explanation
Preconditions: at least one organization key present in `secrets.github` with `webhook_secret` blank/nil — a configuration the repo's own example/setup docs present as acceptable. No Shipit or GitHub secret, session, or privileged role is needed by the attacker; only knowledge (or brute-force discovery via the 422/200 signal) of the org login and a target repository's `full_name`/stack. Cost is a single unauthenticated HTTP POST per probe and per forged event; fully repeatable and scriptable against arbitrary repositories/stacks under that organization.

### Recommendation
Treat a present-but-secretless `webhook_secret` as a configuration error, not a bypass: `GitHubApp#verify_webhook_signature` should fail closed (return `false`, or raise at boot) rather than `return true unless webhook_secret`. Additionally, consider making the controller distinguish "no signature could be verified" uniformly with a 422 regardless of whether the org is unknown or misconfigured, removing the response-code oracle.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb` style (no live GitHub, uses `Shipit.stubs`/fixtures already used elsewhere in that file):

1. Enumeration test:
   - Stub `Shipit.github` to raise `GithubOrganizationUnknown` for org `"totally-unknown-org"`; POST a push payload with that owner login and any `X-Hub-Signature`; assert `assert_response :unprocessable_entity` (mirrors existing test at lines 109-127).
   - Build a real `GitHubApp` instance with `config` containing `app_id`/`installation_id`/`private_key` but no `webhook_secret` (i.e. `webhook_secret: nil`), assign it via `Shipit.stubs(:github).with(organization: 'configured-org').returns(app)`; POST the same push payload with owner login `"configured-org"` and an arbitrary bogus `X-Hub-Signature` value; assert `assert_response :ok` — the two responses are 422 vs 200 for otherwise-identical unauthenticated requests, confirming the equality `verify_webhook_signature(bogus_sig, payload) == true` holds when `webhook_secret` is nil.
2. Exploit test: reuse the fixture stack/repository owned by `"configured-org"`; POST a push webhook payload naming that repository's `full_name` and the tracked branch, with the same missing-secret `GitHubApp`, using a bogus signature; assert that `GithubSyncJob` is enqueued (`assert_enqueued_with`, same pattern as line 23-32) or that a `Status` row is created for a real commit (same pattern as lines 42-59) — demonstrating a full `PushHandler`/`StatusHandler` mutation of that organization's real `Stack`/`Commit` succeeding with no valid signature. [3](#0-2) [4](#0-3)

### Citations

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

**File:** lib/shipit.rb (L170-181)
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
```
