### Title
Webhook signature verification is keyed to an attacker-controlled `repository.owner.login`/`organization.login` field, decoupling the GitHub organization that "authenticates" a request from the repository the event handlers actually act on - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`, a value read straight out of the untrusted, attacker-supplied JSON body. `GitHubApp#verify_webhook_signature` additionally treats a missing/blank `webhook_secret` as automatic success (`return true unless webhook_secret`). Any multi-org Shipit deployment that has at least one configured organization without a `webhook_secret` (a state the shipped example configs explicitly show as valid, e.g. `webhook_secret: # nil`) lets an unauthenticated attacker forge a webhook whose "authenticating organization" is the secret-less org while the `repository.full_name`/name fields used later to locate the `Stack`/`Repository` to act on refer to a different, legitimately secured org/repo.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` resolves the GitHub App/secret to verify against using: [1](#0-0) 
where `repository_owner` is: [2](#0-1) 
i.e. it is read from the same JSON body that is being verified, and it can be either `repository.owner.login` or the fallback `organization.login`.

`Shipit.github(organization: repository_owner)` returns a `GitHubApp` instance whose `verify_webhook_signature` is: [3](#0-2) 
Notice `return true unless webhook_secret` - if the resolved organization's config has no `webhook_secret` set, verification is bypassed entirely, regardless of the actual `X-Hub-Signature` header supplied.

Configuration for multiple organizations sharing one Shipit instance, with some orgs left with a blank `webhook_secret`, is an explicitly documented/expected setup, shown in `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml` (`webhook_secret: # nil` for each org).

Because `repository_owner`/`organization.login` is only used to *select which secret checks the signature*, and is not cryptographically bound to the rest of the payload (there's no secret-specific validation that the org actually matches `repository.full_name`), an attacker can craft a POST body where:
- `repository.owner.login` (or `organization.login`) = an organization configured in this Shipit install with `webhook_secret: nil` → signature check trivially passes with any/no `X-Hub-Signature` header,
- while `repository.full_name` / commit `sha` / branch fields inside the same payload target a `Stack` that actually belongs to a different, secret-protected organization tracked by this Shipit instance.

Since `params` (the full untrusted body) is passed unmodified to the event handler (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`), downstream handlers (push, status, check_suite, membership, etc.) act on whatever repository/commit identifiers are in the payload, not on the organization that was used to authenticate the request. This breaks the intended binding "organization that authenticated == repository that is written," analogous to the audited bug where the paid/verified amount (liens only) and the acted-upon field (`currentBid` = full bid) diverged.

### Impact Explanation
An unprivileged, unauthenticated external attacker can forge GitHub webhook deliveries (push, commit status, check_suite, deployable/merge status) for any `Stack`/repository tracked by the Shipit instance, as long as the instance has any organization configured without a `webhook_secret`. Depending on which handlers are registered, this can:
- Force `GithubSyncJob` to run for arbitrary target commits/branches,
- Inject fake commit statuses/check-suite results that influence `deployable_status`/`merge_status` and downstream automatic merge/deploy gating logic,
- Potentially manipulate the state that governs whether a stack is considered safe to deploy.

This is a real authentication-bypass on the webhook ingestion boundary, and depending on how status/merge automation is used it can lead to an unauthorized deploy/merge decision, satisfying the Critical/High impact bar (auth bypass and influence over `Shipit.github_teams`-gated deploy state via forged status/webhook events).

### Likelihood Explanation
Requires only that the Shipit deployment configures more than one GitHub organization and leaves the `webhook_secret` blank for at least one of them - a configuration explicitly present (and commented as valid, `# nil`) in this engine's own shipped example configs (`config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`). No credentials, GitHub App keys, or Shipit sessions are needed; the attacker only needs network access to the public `/webhooks` endpoint.

### Recommendation
Do not let an attacker-supplied field select the verification secret without binding it cryptographically to the acted-upon repository. Concretely:
- Verify the webhook signature against every configured org's secret (or at minimum require a match against the specific org that owns the `repository.full_name` actually referenced) rather than trusting `repository.owner.login`/`organization.login` from the unauthenticated payload to select the verifier.
- Treat a missing `webhook_secret` as "reject" rather than "always verified" in `GitHubApp#verify_webhook_signature`, or require operators to configure a webhook secret for every organization.
- After signature verification succeeds for organization `O`, assert that the repository referenced in the payload (`repository.full_name`) actually belongs to organization `O` before dispatching to handlers.

### Proof of Concept
1. Deploy Shipit with two configured GitHub organizations, `SecureOrg` (has `webhook_secret` set) and `OpenOrg` (has `webhook_secret` left blank, as in the shipped example configs).
2. `SecureOrg/target-repo` is tracked as a `Stack` in this Shipit instance.
3. Attacker sends:
   ```
   POST /webhooks
   X-Github-Event: push
   X-Hub-Signature: sha1=anything-or-omitted
   {
     "repository": { "owner": { "login": "OpenOrg" }, "full_name": "SecureOrg/target-repo", ... },
     "after": "<attacker-chosen-sha>",
     "ref": "refs/heads/main"
   }
   ```
4. `verify_signature` computes `repository_owner = "OpenOrg"`, calls `Shipit.github(organization: "OpenOrg").verify_webhook_signature(...)`, which returns `true` immediately because `OpenOrg`'s `webhook_secret` is blank.
5. The unmodified `params` (still referencing `SecureOrg/target-repo`) are passed to the push handler, which enqueues sync/processing for `SecureOrg/target-repo` based on the attacker-chosen `after` SHA, despite the request never being validated against `SecureOrg`'s real webhook secret. [4](#0-3)

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
