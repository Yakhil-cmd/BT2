### Title
Webhook signature verification keys off `repository.owner.login`/`organization.login` while event handlers act on the unrelated `repository.full_name` field, letting an attacker with one organization's webhook secret trigger syncs/deploys on a victim organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `github_app` (and therefore which `webhook_secret`) to validate the `X-Hub-Signature` against by reading `repository.owner.login` (falling back to `organization.login`) straight out of the untrusted, not-yet-verified JSON body. Every downstream `Shipit::Webhooks::Handlers::Handler` subclass, however, resolves the `Repository`/`Stack` to act on using a *different* field of the same body: `repository.full_name`. Because these two fields are never cross-checked against each other, the field that determines "whose secret authenticates this payload" and the field that determines "which repository/stack gets acted on" are decoupled — exactly the push/pull-style binding break the external report is analogous to (a value used for the trust check vs. a different value used for the effect).

### Finding Description
`verify_signature` computes the signing organization purely from body content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns the `GithubApp`/`GithubOrganization` instance configured for that name, and `verify_webhook_signature` checks the HMAC using **that org's own `webhook_secret`**: [3](#0-2) 

After the signature passes, `create` hands the same raw body to the matching handler(s): [4](#0-3) 

But every handler resolves the repository/stack to operate on from a completely different key, `repository.full_name`, not `repository.owner.login`: [5](#0-4) [6](#0-5) 

`PushHandler#process` uses that repository's stacks to call `sync_github`: [7](#0-6) 

and `PullRequest::ClosedHandler` likewise resolves its `repository`/`review_stack` from `params.repository.full_name`, independent of the owner used for signature verification: [8](#0-7) 

The engine explicitly supports hosting multiple GitHub organizations, each with its own distinct `webhook_secret`, on a single Shipit instance: [9](#0-8) 

Binding that should hold: `organization whose webhook_secret authenticated the request == organization that owns the repository/stack being acted on`. Before the attack this equality trivially holds because GitHub always sends a consistent `repository.owner.login`/`full_name` pair for a real event. After the attack, an attacker who legitimately administers Org A (and thus legitimately knows Org A's `webhook_secret`, e.g. because they installed the same GitHub App on their own org on a shared, multi-org Shipit instance) can POST a payload where `repository.owner.login = "orgA"` (so the signature check selects and validates against Org A's secret, which the attacker can correctly HMAC-sign) while `repository.full_name = "orgB/victim-repo"` (a different, victim organization also configured on the same instance). The signature check passes, but the handler acts on Org B's `Repository`/`Stack`.

### Impact Explanation
This breaks the authentication↔authorization binding at the organization level: a party authenticated only as Org A causes side effects scoped to Org B's stacks, meeting the High-severity criterion of "escalation into `Shipit.github_teams` authorization" analog / cross-tenant action without the corresponding credential. Concretely, via `PushHandler`, the attacker can force `stack.sync_github(expected_head_sha: params.after)` on any of Org B's stacks, and via other handlers (e.g. `PullRequest::ClosedHandler`) can archive/mutate Org B's review stacks — all without ever possessing Org B's `webhook_secret`, GitHub App credentials, or repository access. Depending on stack configuration (e.g., continuous deployment/auto-merge enabled on sync), this can escalate into triggering deploy/merge activity on a repository the attacker does not control, which aligns with the report's "unauthorized deploy" impact class.

### Likelihood Explanation
This requires a multi-organization Shipit deployment (explicitly documented and supported) where the attacker legitimately controls at least one of the configured organizations' GitHub App/webhook secret — a realistic scenario for shared Shipit instances used by multiple orgs/teams. No GitHub write access, API token, or session to the victim org is required; only a POST to the public `/webhooks` endpoint with a crafted `repository` object and a valid signature computed with the attacker's own known secret.

### Recommendation
Bind the signature-verification key and the resource-resolution key to the same field. Either:
1. Derive `repository_owner` in `verify_signature` from `repository.full_name`'s owner segment (the same field handlers use), or
2. After signature verification succeeds, re-validate that `repository.owner.login`/`organization.login` matches the owner segment of `repository.full_name` before dispatching to handlers, rejecting (422) on mismatch.

### Proof of Concept
1. Configure Shipit with two orgs in `config/secrets.yml`: `orgA` (secret known to attacker, who administers a GitHub App install on `orgA`) and `orgB` (victim, with stacks configured for `orgB/victim-repo`).
2. Attacker crafts a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(orgA_webhook_secret, raw_body)` using the secret they legitimately hold for `orgA`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "orgA")` (from `repository.owner.login`), signature checks out, request proceeds.
6. `PushHandler#process` resolves `Repository.from_github_repo_name("orgB/victim-repo")` from `full_name`, and calls `stack.sync_github(expected_head_sha: ...)` on Org B's stacks — an action the attacker had no credentials for.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-59)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

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
