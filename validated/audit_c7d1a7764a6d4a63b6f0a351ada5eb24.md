### Title
Webhook signature verification is bound to `repository.owner.login`, but event handlers act on the unverified `repository.full_name` - allowing cross-repository forged webhook events ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The bug class in the report is a hash/signature computed over one representation of data while a different, unbound representation is later trusted for actions — a padding/delimiter confusion that lets two different logical inputs produce the same verified digest. Shipit's webhook pipeline has the analogous binding break: the HMAC signature check picks *which organization's secret* to use based on `repository.owner.login` (or `organization.login`), but every event handler subsequently resolves the *actual* repository/stack to act on using the independent, unauthenticated `repository.full_name` field. Nothing ties these two fields together, so a signature that is valid for organization A's webhook secret can carry a payload whose `repository.full_name` names a repository belonging to organization B.

### Finding Description
`WebhooksController#verify_signature` derives the signing organization purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

It looks up `Shipit.github(organization: repository_owner)` and verifies the raw body against *that organization's* `webhook_secret`: [3](#0-2) 

Once the signature is accepted, control passes to the registered handler for the event (`push`, `status`, `check_suite`, `pull_request`, etc.). These handlers never re-check `repository.owner.login`; instead they resolve the target repository purely from `repository.full_name`: [4](#0-3) [5](#0-4) 

For example `PushHandler` uses `stacks` (built from `full_name`) to sync arbitrary stacks: [6](#0-5) 

and `CheckSuiteHandler`/pull-request handlers similarly resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` independent of the field used for signing: [7](#0-6) [8](#0-7) 

The binding that is supposed to hold is: `organization authenticated by HMAC == owner of the repository the handler mutates`. In reality:
- Before the PR/request: for a legitimate GitHub webhook, `repository.owner.login` and the owner segment of `repository.full_name` are always identical, produced server-side by GitHub — the binding accidentally holds because GitHub itself enforces it.
- After the attacker's forged request: an attacker who is an admin of *any* organization onboarded to this multi-tenant Shipit instance (configured in `config/secrets.yml`, e.g. `someothergithuborg`) knows that organization's real `webhook_secret` (it is visible to them when creating/configuring the GitHub App on their own org, per `docs/setup.md`). They can POST a raw JSON body where `repository.owner.login` = their own org (so `verify_signature` picks their own known secret and the HMAC validates) but `repository.full_name` = `"victim-org/victim-repo"` (an org/repository they do not control), which is what every handler actually acts on.

This is architecturally identical to the reported Move-package bug: the verified quantity (owner login) and the acted-upon quantity (full_name) are logically supposed to be the same value but are never cryptographically tied together, so an attacker can make them diverge while the check still passes.

### Impact Explanation
This lets an attacker with a legitimate GitHub App installation for *any one* organization onboarded to a shared Shipit instance forge webhook events that are processed as if they came from GitHub for a *different* organization's repository/stack. Concretely:
- Forged `push` events can trigger `stack.sync_github(expected_head_sha: params.after)` for stacks that belong to a repository the attacker does not control, which drives commit ingestion and continuous-delivery evaluation for that unrelated repository/stack — a cross-repository state-changing action driven entirely by attacker-forged input.
- Forged `check_suite`/`pull_request` events can archive/unarchive review stacks or trigger check-run refreshes for arbitrary review stacks belonging to any repository configured on the instance.

Because this can drive Shipit into acting on a repository/stack outside the boundary that the webhook signature was supposed to authorize, it constitutes a cross-repository write reachable by an attacker who has never been granted write access to the target repository or organization, matching the report's "Critical: cross-repository writes" bar.

### Likelihood Explanation
Exploitability requires the attacker to control a GitHub organization that is one of the (potentially many) organizations configured in this Shipit instance's `secrets.yml` (`Shipit.github(organization: ...)` supports multiple orgs, as shown by `config/secrets.development.shopify.yml`). Any such org admin can view/rotate their own app's webhook secret and thus sign arbitrary payloads. No access to the victim organization, the victim's repository, a Shipit session, or an `ApiClient` token is required, which satisfies the "unprivileged attacker" bar defined in the rules.

### Recommendation
Bind the verified identity to the acted-upon resource: after `verify_webhook_signature` succeeds for organization `repository_owner`, every handler that resolves a `Repository`/`Stack` from `repository.full_name` must assert that the owner segment of `full_name` equals the `repository_owner` (or `organization.login`) that was used to select the verifying secret, rejecting (422) the request otherwise. Equivalently, pass the verified organization down to `Handler#stacks`/`#repository_name` and scope repository lookups to it rather than trusting `full_name` in isolation.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `attacker-org` and `victim-org` (`config/secrets.yml`), each with its own `webhook_secret`. Attacker is an admin of `attacker-org` and knows `attacker-org`'s `webhook_secret`; a Stack exists for `victim-org/victim-repo`.
2. Attacker crafts a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` reads `repository_owner` = `"attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and the HMAC validates (attacker knows this secret) — see [1](#0-0) .
5. `Shipit::Webhooks::Handlers::PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` (see [5](#0-4)  and [6](#0-5) ) and calls `stack.sync_github(expected_head_sha: "deadbeef...")` for the victim's stack — a cross-organization side effect produced from a signature that only ever proved knowledge of `attacker-org`'s secret.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
