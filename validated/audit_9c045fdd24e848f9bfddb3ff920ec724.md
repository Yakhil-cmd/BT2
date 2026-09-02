### Title
Webhook signature verified against organization named in payload while handlers act on a different repository named in the same payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Finding Description
The webhook signature check and the actual repository/stack lookup are driven by two independent, uncorrelated fields inside the same attacker-controlled JSON body.

`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC against using `repository_owner`, which reads `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`): [1](#0-0) [2](#0-1) 

Each organization configured in Shipit has its own `webhook_secret` (`Shipit.github(organization: ...)`), so `verify_webhook_signature` only proves the request was signed with the secret belonging to whatever organization the `repository.owner.login` (or `organization.login`) field claims - not the repository the payload actually targets: [3](#0-2) 

After signature verification passes, `create` dispatches the parsed body to handlers, e.g. `PushHandler`, which resolve the target repository/stacks from a *different* field, `payload.dig('repository', 'full_name')`, via `Handler#repository_name`/`#stacks`: [4](#0-3) [5](#0-4) 

`repository.owner.login`/`organization.login` (used for signature/secret selection) and `repository.full_name` (used for the actual stack lookup) are never cross-checked against each other. An attacker who legitimately knows/controls the `webhook_secret` for one organization onboarded to this Shipit instance (e.g. because they administer that org's GitHub App/webhook settings) can craft a raw POST body where `organization.login` / `repository.owner.login` = their own organization (so the HMAC check passes using a secret they know), while `repository.full_name` = `"victim-org/victim-repo"`, a completely different, unrelated repository/stack tracked by the same Shipit instance. Since `Repository.from_github_repo_name` looks up strictly by the `full_name` string, the handler will act on the victim repository's stacks despite the signature only proving control over the attacker's own organization's secret.

This is the direct analog of the M-17 bug class: a value that is checked/verified (the "rate"/organization identity backing the signature) is decoupled from the value that is actually acted upon (the repository/stack that receives the side effect), and the code never re-verifies that the two match before performing state-changing actions.

### Impact Explanation
Using `PushHandler`, the attacker can enqueue `stack.sync_github(expected_head_sha: params.after)` for any stack under the victim repository whose `branch` matches, effectively forging a push signal (with an attacker-chosen SHA) for a repository they never authenticated against: [6](#0-5) 

`StatusHandler`/`CheckSuiteHandler` similarly key off `repository.full_name`-derived stacks and commit SHAs supplied entirely by the attacker, allowing forged CI/commit status updates or forced check-run refreshes on commits belonging to the victim repository - status data that Shipit's `continuous_deployment` / `deployable?` gating relies on to decide whether a commit is safe to auto-deploy. Because commit statuses influence whether Shipit considers a commit "deployable" and continuous deployment can act on that, an attacker forging `status` webhooks for a repository they don't administer can manipulate deploy eligibility for that repository, which corresponds to the "unauthorized deploy" Critical-impact category defined in the rules. The severity depends on which handler is reached and how strongly downstream logic trusts the forged event, but the core authentication-bypass primitive (organization-that-signed vs. repository-that-is-acted-upon) is concretely reachable through the public, unauthenticated `/webhooks` endpoint.

### Likelihood Explanation
Requires only that the attacker legitimately possess a `webhook_secret` for **any** organization configured on the target Shipit instance (a routine, low-privilege capability if Shipit multi-tenants several orgs, since each org owner independently manages their own GitHub App/webhook secret) and that the target Shipit instance also hosts a repository from another organization. No repository write access, GitHub App private key, or Shipit session/API token is needed - only knowledge of one org's webhook secret, which the rules explicitly do not exclude (it is not `webhook_secret`/`api_clients_secret` of the app itself, but a per-organization value the attacker is expected to hold for their own org).

### Recommendation
Cross-validate that the organization used to select the verifying secret matches the owner embedded in `repository.full_name` (or `organization.login`) before dispatching to handlers - e.g. `verify_signature` should compare `repository_owner` against the parsed `repository['full_name'].split('/').first` and reject (422) on mismatch, or handlers should re-derive the target repository strictly from the same field that was cryptographically bound to the verified organization, rather than trusting an independent `full_name` string from the unauthenticated payload.

### Proof of Concept
1. Shipit instance is configured with two organizations, `attacker-org` (attacker knows `webhook_secret_A`) and `victim-org` (repository `victim-org/victim-repo` has a stack tracked in Shipit).
2. Attacker crafts a JSON push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "organization": { "login": "attacker-org" },
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_A, raw_body)>` using the secret they legitimately know for `attacker-org`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature [7](#0-6) .
5. `PushHandler.process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues a `sync_github(expected_head_sha: "<attacker-chosen sha>")` job for the victim's stack [6](#0-5)  - despite the attacker never having authenticated against `victim-org`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-23)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
```
