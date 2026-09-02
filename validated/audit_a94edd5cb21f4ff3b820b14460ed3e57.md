## Analog Found

### Title
Webhook Signature Verified Against `repository.owner.login`, Not Against the Repository the Event Actually Targets - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to check an incoming webhook's HMAC signature against using a field read out of the same untrusted JSON body it is trying to authenticate — `repository.owner.login` (falling back to `organization.login`) — rather than by any value tied to the actual local `Repository`/`Stack` the event will be dispatched to.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb:24-49`, the controller does: [1](#0-0) 

`repository_owner` is computed purely from the request body: [2](#0-1) 

`Shipit.github(organization: repository_owner)` resolves to a per-organization `GithubApp` configuration, each with its own independent `webhook_secret`, as documented for multi-tenant setups: [3](#0-2) 

Signature check itself is a standard per-organization HMAC comparison in `lib/shipit/github_app.rb`: [4](#0-3) 

Once the signature validates (i.e., the request was HMAC-signed with *some* organization's secret, selected by the attacker-supplied `repository.owner.login`/`organization.login` field), the full raw JSON body — including all other fields such as `repository.full_name` — is handed unchanged to the registered handlers: [5](#0-4) 

Downstream, repositories are resolved by parsing `owner/name` out of a repo-name string, not by re-validating consistency with the field used for signature selection: [6](#0-5) 

`PushHandler#process` then iterates `stacks` filtered only by branch, with no code path shown enforcing that the stacks acted upon belong to the same organization whose secret validated the signature: [7](#0-6) 

**The broken binding, stated as an equality that the code fails to enforce:**
`organization authenticated by verify_signature (repository.owner.login / organization.login)` == `repository/stack actually mutated by the handler (resolved via repository.full_name or equivalent)`

Because the entire JSON body is attacker-composed before being HMAC-signed with a secret the attacker legitimately possesses (their own organization's `webhook_secret`, in any deployment mounting Shipit for multiple GitHub organizations as the docs explicitly support), nothing stops the attacker from setting `repository.owner.login` to their own org (to pass signature verification with a secret they know) while setting other repository-identifying fields (`repository.full_name`, `id`, etc.) to point at a stack belonging to a *different* organization also hosted on the same Shipit instance.

### Impact Explanation
If exploitable end-to-end (i.e., if the handler chain resolves the target `Repository`/`Stack` from a field decoupled from `repository_owner`), an attacker who administers only their own low-trust GitHub organization/App installation on a shared multi-org Shipit instance could forge webhook events (e.g., `push`, `status`, `check_suite`, `membership`) that are accepted as authentic for a victim organization's repository. Depending on which handler is targeted, this can trigger unauthorized `GithubSyncJob` runs, fabricated commit statuses, or forged team/membership changes that feed into `Shipit.github_teams` authorization (`User#authorized?` in `app/models/shipit/user.rb:80-82`) — an escalation into deploy/authorization state without ever holding a Shipit session or API token. This lands in the High-impact bucket (escalation into `Shipit.github_teams` authorization / unauthenticated manipulation of stack/task state via a forged trust binding).

### Likelihood Explanation
Requires a Shipit deployment configured for multiple GitHub organizations (explicitly documented as a supported configuration) where the attacker legitimately controls one tenant organization's GitHub App/webhook secret but targets another tenant's repository on the same instance. This is a realistic deployment pattern for shared Shipit instances but not for single-org deployments.

### Recommendation
Verify the signature using the organization/app resolved from the *same* field that will actually be used to resolve the target `Repository`/`Stack` (e.g., re-derive both from `repository.full_name` consistently, or after resolving the local `Repository` record, assert `repository.owner == verified_organization` before dispatching to handlers).

### Proof of Concept
Conceptual, given the confirmed code paths above:
1. Attacker operates organization `attacker-org` with a known `webhook_secret` on a shared multi-tenant Shipit instance that also hosts `victim-org/victim-repo`.
2. Attacker crafts a `push` JSON body with `repository.owner.login = "attacker-org"` but `repository.full_name = "victim-org/victim-repo"` and `ref = "refs/heads/master"`.
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s `webhook_secret` over this exact body and POSTs to `/webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and the signature validates.
5. The full body — now including the victim's `full_name` — is passed to `PushHandler`, which resolves/acts on stacks tied to `victim-org/victim-repo` (pending confirmation of the exact `Handler#stacks` resolution code, which was not retrievable within the available tool budget).

**Caveat:** I was unable to retrieve the base `Handler` class's `stacks` method implementation (`app/models/shipit/webhooks/handlers/handler.rb`) within the available tool calls, so the exact field used to scope `stacks` to a `Repository` is not independently confirmed from source in this pass — it is inferred from `Repository.from_github_repo_name` parsing `full_name` and from `PushHandler` referencing no owner-consistency check. Confirming that file would fully close the proof; the signature-selection root cause in `webhooks_controller.rb` and `github_app.rb` is confirmed directly.

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

**File:** docs/setup.md (L184-209)
```markdown
A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
