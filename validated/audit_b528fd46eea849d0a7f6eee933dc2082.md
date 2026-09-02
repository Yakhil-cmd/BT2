### Title
Cross-organization webhook forgery via mismatched signature-selection field and repository-resolution field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
The GitHub webhook signature is verified using an HMAC secret selected from `repository.owner.login` (or `organization.login`) in the payload, but the code that actually resolves which `Stack`/`Repository` the event applies to reads a *different* field — `repository.full_name` — from the same unauthenticated JSON body. In a multi-org Shipit deployment (`Shipit.github(organization:)` supports multiple orgs, each with its own `webhook_secret`, as seen in `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`), nothing forces `full_name`'s owner segment to match `owner.login`. An attacker who legitimately controls one onboarded GitHub organization (and therefore knows/can trigger a validly-signed webhook for it) can forge a payload whose `owner.login` matches their own org (so the correct, attacker-known secret is used to pass `verify_signature`) while `repository.full_name` points at a different, victim organization's repository tracked by the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` in [1](#0-0)  picks the HMAC secret to validate against via `repository_owner`: [2](#0-1) 

Signature verification itself, in `GitHubApp#verify_webhook_signature`, only checks the byte-for-byte HMAC of the raw body against the secret configured for whatever organization `repository_owner` claims to be: [3](#0-2) 

Crucially, the signature covers the *entire raw payload bytes*, but the security decision "which org's secret proves authenticity" is made by reading one JSON field (`repository.owner.login`) out of that same, not-yet-verified payload — before the signature has even been checked against the org it names. The downstream handler that decides *which Shipit `Stack` gets written to* uses a *different* field, `repository.full_name`, entirely independent of `repository.owner.login`: [4](#0-3) 

Nothing in `WebhooksController`, `Handler`, or `PushHandler`/`StatusHandler` cross-checks that `full_name`'s owner segment equals `owner.login`. This is structurally the same class of bug as the report: the artifact that is authenticated (the org key used for HMAC selection) does not match, and is never bound to, the artifact that is actually acted upon (the repository resolved for writes). Just as the zkEVM sequencer's identity was omitted from the proven public inputs allowing a different address to claim credit for someone else's finalized blocks, here the target-repository identity is omitted from what the signature effectively "proves," allowing an attacker who owns Org A's webhook secret to forge events that are applied to Org B's tracked repositories/stacks.

`PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on the matching branch: [5](#0-4) 
This can trigger sync of commit history and, on stacks with continuous deployment enabled, an actual deploy of the (real, existing) commit named in the forged `after` SHA — for a repository the attacker does not control and was never meant to be able to influence. `StatusHandler` similarly lets the attacker inject arbitrary CI status for any commit SHA already known to Shipit, which can flip CI-gating logic (`required_statuses`) used by `DeploySpec` to decide whether a deploy is safe/mergeable: [6](#0-5) 

### Impact Explanation
This crosses the "cross-repository writes" / "unauthorized deploy" Critical bar: an attacker with legitimate but limited GitHub App/webhook access to one organization tracked by a shared multi-org Shipit instance can forge webhook events (push, status, check_suite) that are applied to a *different* organization's stacks — triggering unintended deploys of pre-existing commits (via continuous deployment) and forging CI/status data used to gate deploy safety checks, without ever needing the victim org's webhook secret, an `ApiClient` token, or repository write access to the victim repo.

### Likelihood Explanation
Requires the Shipit instance to be configured with multiple GitHub orgs/apps (a documented, supported configuration — see `config/secrets.development.shopify.yml` and `secrets_double_github_app.yml`), and requires the attacker to control (or have push access enabling webhook delivery for) at least one of those onboarded organizations/repos. This is a realistic scenario for shared/central Shipit deployments serving multiple teams or business units, each with separate GitHub orgs, since any one of those orgs' legitimate webhook senders is an "unprivileged attacker" with respect to every other org's stacks.

### Recommendation
In `WebhooksController#verify_signature` and/or `Handler#repository_name`, enforce that `repository.owner.login` (or `organization.login`, whichever selected the HMAC secret) matches the owner segment of `repository.full_name` before processing the event; reject with 422/`Unprocessable` on mismatch. This binds the field used to select/prove the signing secret to the field used to determine the write target, closing the gap analogous to including the sequencer's address in the proven public input hash.

### Proof of Concept
1. Shipit instance configured with two orgs, `OrgA` (attacker-controlled) and `OrgB` (victim), each with its own `webhook_secret`, both tracking a stack.
2. Attacker crafts a JSON payload: `repository.owner.login = "OrgA"`, `repository.full_name = "OrgB/victim-repo"`, `ref = "refs/heads/main"`, `after = "<existing sha attacker wants deployed>"`.
3. Attacker computes `X-Hub-Signature` using OrgA's known webhook secret over this exact payload and POSTs to `/github/webhooks`.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches OrgA's `GitHubApp`, and the signature validates successfully (attacker crafted it correctly for OrgA's secret): [7](#0-6) 
5. `PushHandler#process` resolves the target stacks via `payload.dig('repository', 'full_name')` = `"OrgB/victim-repo"`, not `"OrgA"`, and calls `sync_github`/triggers deploy on OrgB's stack: [8](#0-7)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/deploy_spec.rb (L194-196)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end
```
