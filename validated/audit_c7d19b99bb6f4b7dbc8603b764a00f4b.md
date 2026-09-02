### Title
Cross-organization webhook forgery via organization/repository binding mismatch in signature verification - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to verify the HMAC signature against by reading `repository.owner.login` (or `organization.login`) out of the **unverified** JSON body, but the event handlers that subsequently act on the payload look up the target `Repository`/`Stack` using the *different* field `repository.full_name`. Nothing enforces that these two fields refer to the same organization, so a party who knows the `webhook_secret` for one organization configured in Shipit can forge a signed payload whose `repository.full_name` points at a repository belonging to a completely different organization also hosted on the same Shipit instance, causing Shipit to archive/unarchive/deprovision review stacks or trigger syncs for that unrelated repository.

### Finding Description
`verify_signature` picks the `GitHubApp` config to validate against using a field taken straight from the attacker-supplied JSON body, before the signature has been checked: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` then checks the HMAC-SHA1 of the *entire* raw body against the secret of that selected organization: [3](#0-2) 

Once the signature passes, the full (attacker-controlled) `params` hash is dispatched to every registered handler for the event: [4](#0-3) 

However, the base `Handler` class and every `pull_request`/`push` handler resolve the actual `Repository`/`Stack` to operate on using a *different* field, `repository.full_name`, not `repository.owner.login`: [5](#0-4) [6](#0-5) [7](#0-6) 

The invariant that should hold — "organization whose secret authenticated the request" == "organization that owns the repository being written to" — is never enforced. `repository.owner.login` and `repository.full_name` are two independent, attacker-controlled strings inside the same JSON body; only the raw bytes of the body as a whole are covered by the HMAC, so an attacker who legitimately knows the `webhook_secret` for Organization A (e.g. because they administer the same shared GitHub App installation, or Shipit is configured per the documented multi-organization setup with one webhook secret per org) can construct a payload where `repository.owner.login = "OrgA"` (used only to pick which secret verifies the signature) while `repository.full_name = "OrgB/some-repo"` (used to pick which real `Stack`/`Repository` record is mutated). Because the attacker controls the whole raw body and knows OrgA's secret, they can compute a signature that satisfies `verify_signature` while the payload content targets OrgB.

This is the same class of bug as the reNFT finding: a value that is *used to authorize/select the verification context* is not the same value that is *bound into the hash/signature and acted upon downstream*, breaking the intended one-to-one binding between the authenticating identity and the entity being mutated.

### Impact Explanation
This can trigger unauthorized cross-organization writes: `PullRequest::ClosedHandler#process` calls `review_stack.archive!`, and `LabeledHandler`/`ReopenedHandler` can archive/unarchive or provision/deprovision review stacks belonging to a repository/organization the forger has no legitimate relationship with, purely by knowing a webhook secret for an unrelated organization hosted on the same Shipit instance. `PushHandler` can likewise trigger `stack.sync_github` for any stack matching the forged branch/repo. This qualifies as an unauthorized cross-repository write against Shipit's data/infrastructure state, matching the "cross-repository writes" criterion.

### Likelihood Explanation
Exploitability requires the attacker to know one organization's `webhook_secret` configured on the Shipit instance — a realistic scenario for the documented multi-organization deployment mode (`docs/setup.md`, "Using Multiple Github Applications") where each org's GitHub App admin independently possesses their own secret but all hit the same shared `/webhooks` endpoint and shared handler code operating on `repository.full_name` across all configured organizations/repositories. No repository write access, session, or `ApiClient` token is needed — only the webhook secret for any one configured org.

### Recommendation
After verifying the signature, re-derive the organization from the field actually used by the handlers (`repository.full_name`'s owner segment, or resolve the matching `Repository`) and confirm it matches the organization/app config (`repository_owner`) whose secret validated the signature; reject the request if they differ. Alternatively, bind webhook validation strictly per-repository (verify against the specific `Repository`'s configured secret keyed by `full_name`, not by `owner.login`/`organization.login` alone) so the value used for verification and the value used for the write are the same.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md` multi-app setup).
2. As someone who knows `OrgA`'s `webhook_secret` (e.g. an admin of the GitHub App installed on OrgA), craft a `pull_request` "closed" JSON payload where:
   - `repository.owner.login = "OrgA"`
   - `repository.full_name = "OrgB/target-repo"`
3. Compute `X-Hub-Signature: sha1=<hmac_sha1(OrgA_webhook_secret, raw_body)>` over the full crafted body.
4. POST to `/webhooks` with header `X-Github-Event: pull_request`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches OrgA's `GitHubApp`, and the signature validates successfully against OrgA's secret.
6. `Shipit::Webhooks::Handlers::PullRequest::ClosedHandler` resolves `Shipit::Repository.from_github_repo_name("OrgB/target-repo")` and calls `review_stack.archive!`, archiving a review stack belonging to `OrgB` — an organization the attacker has no legitimate access to — despite the request only being authenticated for `OrgA`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
