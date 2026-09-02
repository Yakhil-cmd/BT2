### Title
Webhook signature is verified against the organization named in the payload while the payload's `repository.full_name` (a different, unverified field) is used to locate the Stack that gets written to — allowing cross-organization event forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to check the HMAC signature against using `repository_owner`, a value read directly out of the untrusted JSON body (`repository.owner.login` or `organization.login`). Every webhook handler, however, resolves the actual `Repository`/`Stack` to mutate using a *different* field from the same body, `repository.full_name`, via `Handler#repository_name` and `Repository.from_github_repo_name`. Nothing ties these two fields together, so a payload can be legitimately signed for organization A while pointing its `repository.full_name` at a stack that belongs to organization B.

### Finding Description
`WebhooksController#verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [1](#0-0) 
where `repository_owner` is taken straight from the JSON body before any signature check has occurred: [2](#0-1) 

`verify_webhook_signature` only checks that the raw body's HMAC matches the secret configured for that one organization: [3](#0-2) 

Once verification passes, the event is dispatched to handlers with the *whole, attacker-controlled* JSON body: [4](#0-3) 

Every `Handler` subclass then resolves the target repository/stack using `repository.full_name`, a field that was never bound to `repository_owner` at signature-verification time: [5](#0-4) [6](#0-5) 

For example `PushHandler` triggers a sync on any stack matching `repository.full_name`/branch: [7](#0-6) 

Because Shipit is multi-tenant (one GitHub App/secret configured per organization via `Shipit.github(organization:)`), the binding the system relies on is: *the organization whose secret validated the signature* == *the organization that owns the repository being written to*. That equality is never enforced — the signature only proves "some payload signed with org A's secret", while the mutation is applied to whatever `repository.full_name` says, which can name org B's repository.

This is the direct analog of the reported `ParticleExchange.onERC721Received()` bug: there, the contract trusted that reaching `onERC721Received()` implied the NFT was actually transferred, without checking the binding between "callback fired" and "asset actually received." Here, Shipit trusts that "signature verified for organization X" implies "the payload's target repository belongs to organization X," without checking that binding either.

### Impact Explanation
An entity that legitimately owns/administers a GitHub organization already connected to this Shipit instance (and thus knows the webhook secret they configured for their own org's webhook delivery — an action requiring no Shipit privilege) can forge a `status` or `push` webhook naming a *different* organization's repository in `repository.full_name`. Handlers like `StatusHandler`/`Commit#create_status_from_github!` write CI status directly from attacker-supplied payload fields, and `Commit#add_status` can trigger `stack.schedule_merges` / continuous-deployment scheduling once a commit is marked `success`: [8](#0-7) 
This can force an unauthorized deploy/merge decision on a stack the attacker never had write access to — a cross-organization write reachable purely by controlling one org's webhook secret, satisfying the Critical "cross-repository writes / unauthorized deploy" bar.

### Likelihood Explanation
Requires the attacker to control (or know the webhook secret of) at least one GitHub organization already onboarded to the shared Shipit instance — a realistic scenario for any Shipit deployment serving multiple organizations/teams, since setting up that org's webhook secret is a normal, unprivileged administrative action within that org's own GitHub settings, not a Shipit privilege.

### Recommendation
Bind the field used to select the verification secret to the field used to resolve the target repository: after selecting `github_app` from `repository_owner`, re-verify that every handler's resolved `repository.full_name` owner matches `repository_owner` (or vice versa — derive both from the same trusted field) before dispatching to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` in `app/controllers/shipit/webhooks_controller.rb`.

### Proof of Concept
1. Attacker administers GitHub organization `attacker-org`, which is a legitimate tenant configured in this Shipit instance with its own `webhook_secret` (`S_attacker`), known to the attacker because they configured it.
2. Attacker crafts a `status` webhook JSON body with:
   - `organization.login` / `repository.owner.login` = `attacker-org`
   - `repository.full_name` = `victim-org/production-repo`
   - `sha`, `state: "success"`, forged CI context for a real commit on `victim-org/production-repo`'s tracked stack.
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_attacker, raw_body)` and POSTs to `/webhooks`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')`, which succeeds because the signature matches `S_attacker`.
5. `Shipit::Webhooks.for_event('status')` handler runs against the full payload, using `repository.full_name = 'victim-org/production-repo'` to find and mutate `victim-org`'s commit/stack state, potentially triggering `schedule_merges`/CD for a stack the attacker never had access to.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/commit.rb (L366-384)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
