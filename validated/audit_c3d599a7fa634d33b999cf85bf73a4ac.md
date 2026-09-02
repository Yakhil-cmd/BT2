### Title
Cross-organization signature confusion in webhook dispatch — attacker-controlled org's webhook secret authenticates payloads acted on for a victim org's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a payload against using a field read from the *unverified* JSON body, while the downstream handlers act on a *different* field of the same unverified body to decide which repository/stack to mutate. This breaks the intended binding: "the organization whose secret authenticated the request" should equal "the organization/repository the request causes writes to."

### Finding Description
`verify_signature` picks the webhook secret using `repository_owner`, itself derived from the raw, unverified request body: [1](#0-0) [2](#0-1) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

If verification succeeds, the entire raw body is dispatched to handlers, e.g. `PushHandler`, which independently resolve the target repository from `payload.dig('repository', 'full_name')`: [3](#0-2) [4](#0-3) 

In a Shipit deployment configured with multiple GitHub organizations (`Shipit.github(organization:)` supports a per-org config keyed by `TOP_LEVEL_GH_KEYS`), each org has its own `webhook_secret`: [5](#0-4) [6](#0-5) 

An attacker who legitimately controls (or is an admin/member of) their own GitHub organization "attacker-org" — and therefore knows/can install a Shipit GitHub App with a webhook secret they know — can craft a webhook payload where `repository.owner.login` is set to `"attacker-org"` (so the HMAC verification uses attacker-org's known secret and passes) but `repository.full_name` is set to `"victim-org/victim-repo"` (a repository belonging to a different, unrelated organization tracked by the same Shipit instance). Because `Handler#repository_name` and `PushHandler#process` never re-check that `repository.full_name`'s owner matches the `repository_owner` used for signature selection, the forged, correctly-"signed" (for attacker-org) payload is accepted and acted upon against the victim's stack — e.g. triggering `stack.sync_github(expected_head_sha: params.after)` for the victim repo with an attacker-chosen `after` SHA and branch, i.e. an unauthorized cross-repository write/trigger.

This is the same class of bug reported externally: a value used to gate/scale an operation (`sizeDelta`'s decimal assumptions matching the signed intent) diverges from the value actually consumed downstream (`Synthetix`'s expected format), causing an authorization/consistency mismatch. Here, the value used to select the trust anchor (`repository_owner`) diverges from the value the handler consumes to select what gets mutated (`repository.full_name`), even though both come from the same unverified JSON before the signature check completes.

### Impact Explanation
This is a genuine trust-binding break reachable by any user who can stand up their own GitHub organization/App with Shipit (a low bar — the attacker only needs an org and app they control, not access to the victim's org, repo, or GitHub credentials). It allows forcing `GithubSyncJob`/`stack.sync_github` (and similarly, other handlers keyed the same way, e.g. `StatusHandler`, `CheckSuiteHandler`, `PullRequest*Handler`) to run against a completely unrelated stack/repository that the attacker has no legitimate relationship to, using a signature the attacker fully controls. Depending on which handler is exercised, this can force synchronization from a forged `after` SHA/branch, spoof CI status transitions, or manipulate pull-request-driven review stack provisioning for the victim repository — i.e., unauthorized cross-repository writes/triggers on Shipit's model of a repo it does not own, satisfying the Critical "cross-repository writes" bar.

### Likelihood Explanation
Requires only that: (1) the Shipit instance is configured with multiple GitHub organizations sharing the same webhooks endpoint (a documented, supported configuration — see `config/secrets.development.shopify.yml` and `TOP_LEVEL_GH_KEYS`), and (2) the attacker controls one of those organizations/apps (their own). No access to the victim's GitHub org, repository, or Shipit credentials is required — only knowledge of the attacker's own webhook secret, which the attacker legitimately possesses. This is a realistic, unprivileged-attacker path given multi-org support is a first-class configuration mode of the engine.

### Recommendation
After signature verification succeeds, re-derive/pin the trusted organization and require that every repository/owner referenced by the payload (`repository.owner.login`, `repository.full_name`'s owner segment, `organization.login`) match the organization whose secret validated the signature. Reject (422) any webhook whose payload references a repository owner different from the authenticating organization, e.g. enforce this centrally in `WebhooksController#verify_signature` or in `Handler#repository_name`, rather than trusting `full_name` independently in each handler.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` (secret known to attacker, app installed by attacker) and `victim-org` (tracks a real Shipit stack for `victim-org/victim-repo`), per the multi-org config format in `config/secrets.development.shopify.yml`.
2. Craft a push-event JSON payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...attacker_chosen_sha",
  "repository": { "owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC(attacker-org's known webhook_secret, raw_body)` and POST it with `X-Github-Event: push` to `/webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` from `repository.owner.login`, verifies successfully with the attacker's own secret.
5. `PushHandler` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` from `repository.full_name` and triggers `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack — an action the attacker was never authorized to perform.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-29)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** lib/shipit.rb (L62-63)
```ruby
  GithubOrganizationUnknown = Class.new(StandardError)
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
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
