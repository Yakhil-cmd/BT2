### Title
Cross-organization GitHub webhook forgery via secret/repository binding mismatch - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The reported Symmetry bug is a "binding mismatch": the program validates a limited field (`pda_usdc_account`/`pda_token_account` balances) while letting the attacker supply arbitrary other accounts to the same CPI, so the check and the actual effect operate on different data. `WebhooksController` has the same structural flaw: the field used to select **which HMAC secret verifies the signature** (`repository.owner.login` / `organization.login`) is not the same field that downstream handlers use to decide **which stack/repository is mutated** (`repository.full_name`), and nothing re-binds the two after verification.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to validate the request purely from a payload field the request itself supplies: [1](#0-0) [2](#0-1) 

`repository_owner` is read from the untrusted, not-yet-verified JSON body (`params.dig('repository','owner','login')`). This value is used only to look up which `Shipit.github(organization:)` config's `webhook_secret` should validate the signature, via `GithubApp#verify_webhook_signature`: [3](#0-2) 

Once the signature check passes, `create` re-parses the *same* raw body and hands the **entire** payload — including whatever `repository.full_name` value it contains — to the registered event handlers: [4](#0-3) 

Nothing re-checks that the repository/stack ultimately acted on by the handler (resolved from `repository.full_name`, e.g. to enqueue `GithubSyncJob`, create a commit `Status`, or update `deployable_status`) actually belongs to the same organization whose secret was used to authenticate the request. In a Shipit instance serving multiple GitHub organizations with distinct per-organization `webhook_secret`s, this creates the binding break:

`organization that authenticated the HMAC` ≠ `repository/stack that the handler subsequently writes to`

An actor who is only privileged enough to know or read the webhook secret configured for **their own** low-privilege organization (e.g., an org admin who set up the webhook in GitHub's UI, where the secret is visible to them) can compute a valid `X-Hub-Signature` for an arbitrary payload, set `repository.owner.login`/`organization.login` to their own org (so verification passes against their own secret) while setting `repository.full_name` to point at a completely unrelated, higher-value repository/stack tracked in the same Shipit instance. Because HMAC verification and repository resolution consult different sub-fields of the same untrusted body, and no additional check ties the resolved repository back to the authenticated organization, the forged event is processed as if GitHub had genuinely sent it for that other repository.

### Impact Explanation
The impact depends on which `event`/handler processes the forged payload, but concretely:
- A forged `status` event with `state: "success"` for a target SHA in a victim stack that has continuous deployment enabled can satisfy CI requirements and trigger an **unauthorized deploy** of that commit.
- A forged `push` event can enqueue `GithubSyncJob` against a victim stack the attacker does not control, injecting spoofed commit/branch state into Shipit for a repository they have no legitimate authority over.

This matches the "Critical - unauthorized deploy" / "cross-repository writes" impact bar, since it lets an attacker who only controls one organization's webhook configuration act on stacks belonging to a different organization.

### Likelihood Explanation
Requires the deploying instance to host multiple GitHub organizations, each with a distinct configured `webhook_secret` (a supported and expected configuration per `lib/shipit/github_app.rb`'s per-organization `Shipit.github(organization:)` lookup). Any org admin able to view/set their own org's webhook secret in GitHub can attempt this without needing any Shipit credentials, satisfying the "unprivileged attacker" bar. Likelihood is moderate — it depends on multi-tenant deployment and on handlers trusting `repository.full_name` without an org cross-check, which I could not fully trace end-to-end (the push/status handler implementations resolving stacks by full name were not directly inspected due to index/tool limits).

### Recommendation
After `verify_signature` succeeds, re-derive the repository/stack strictly from the organization that was actually used to validate the signature (or, conversely, verify the signature using the organization implied by the repository the handler is about to mutate, not a separate self-reported field), rejecting the webhook if the two disagree.

### Proof of Concept
1. Shipit instance configured with two GitHub App configs: org `attacker-org` (webhook secret known to the attacker as its admin) and org `victim-org` (stack `victim-org/prod-app`, continuous deployment enabled).
2. Attacker crafts a JSON body with `X-Github-Event: status`, `repository.owner.login: "attacker-org"`, `repository.full_name: "victim-org/prod-app"`, `sha: <target commit>`, `state: "success"`.
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s known webhook secret and POSTs to `/webhooks`.
4. `verify_signature` looks up `Shipit.github(organization: "attacker-org")` and validates successfully against the attacker-controlled secret [1](#0-0) .
5. `create` dispatches the full payload (with `repository.full_name` = `victim-org/prod-app`) to the `status` handler [4](#0-3) , creating a spoofed success `Status` on `victim-org/prod-app`'s commit, potentially triggering an unauthorized continuous deploy.

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
