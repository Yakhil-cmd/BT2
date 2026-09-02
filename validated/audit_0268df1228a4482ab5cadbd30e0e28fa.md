### Title
Cross-repository commit status forgery via webhook signature/payload scope mismatch enables unauthorized continuous deployment - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The `github` webhook signature check binds a request to the GitHub *organization* named in the payload's `repository.owner.login` field, but several webhook handlers — most notably `StatusHandler` — never re-validate that the entity being mutated (a `Commit`) actually belongs to that same organization/repository. `StatusHandler` looks up commits **globally by `sha` only**, so an attacker who can produce a validly-signed webhook for *any* org configured in the Shipit instance can forge a CI "status" for a commit belonging to a completely different, unrelated stack/repository.

### Finding Description
`WebhooksController#verify_signature` resolves which org's `webhook_secret` to check against using data taken straight from the untrusted request body: [1](#0-0) [2](#0-1) 

The HMAC verification itself only proves the request was signed by *some* configured organization's secret, using `github_app.verify_webhook_signature(signature, raw_post)`: [3](#0-2) 

Nothing in this flow ties the *content* of the payload to the organization whose secret validated the signature — the org is picked from the same JSON body that the handler later processes. `StatusHandler#process` then acts on that body using **only the commit `sha`**, with no repository/org scoping at all: [4](#0-3) 

So the equality the code implicitly assumes — "organization whose secret signed this payload" == "repository that owns the commit being written" — does not hold. An attacker who owns (or has been added to) any GitHub organization configured in this Shipit instance, or who obtains any one org's `webhook_secret`, can sign an arbitrary `status` event body containing:
- `repository.owner.login` = the org they control (so `verify_signature` picks and passes that org's secret), and
- `sha` = the SHA of a commit belonging to a **different, victim** stack (commit SHAs are public/guessable from the victim repo's GitHub history, PRs, or prior legitimate status/push events).

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` will then create/update a CI status (e.g. `state: "success"`) on the victim's commit, in the victim's stack, even though the attacker never touched the victim's org, repo, or webhook secret.

`Stack#build_deploy` uses `until_commit.deployable?` to decide whether safety checks are bypassed, and continuous delivery is scheduled purely from stack state: [5](#0-4) [6](#0-5) 

If a victim stack has `continuous_deployment: true` and is configured to require a green CI status before shipping, forging a passing status for its latest undeployed commit can cause Shipit to automatically ship that commit — a deploy that was never actually authorized by real CI results for that repository.

### Impact Explanation
This breaks the binding "organization that authenticated the webhook" == "repository whose state is mutated." The practical consequence is a cross-repository/cross-stack write of security-relevant state (a fabricated CI status) performed by an attacker who has no credentials, membership, or webhook secret for the victim's organization — only for some unrelated org configured on the same Shipit instance. Combined with continuous deployment, this can result in an unauthorized deploy of a commit whose CI never actually passed, matching the Critical-impact category ("an unauthorized deploy") defined in scope.

### Likelihood Explanation
Exploitability depends on: (a) the Shipit instance hosting multiple GitHub organizations (a documented, supported configuration — `docs/setup.md` "Using Multiple Github Applications"), and (b) the attacker controlling or knowing the webhook secret for at least one of those orgs (which can be their own, legitimately-added org), and (c) knowing/guessing the victim commit's SHA (trivial for public repos, and often observable via other push/status webhooks or GitHub UI). No access to the victim's Shipit session, API token, or GitHub credentials is required, and no interaction with the host application's mounting configuration beyond the documented multi-org setup is needed.

### Recommendation
Do not derive the org used for signature verification purely from attacker-controlled JSON in the same body being processed for repository-scoped mutations; additionally, every handler that mutates repository/commit state (starting with `StatusHandler`, but also `CheckSuiteHandler`, push, pull_request handlers) must re-validate that the resource being written (`Commit`, `Stack`) belongs to the repository/org that the verified signature was actually checked against, not merely to the org name embedded in the payload. Concretely, `StatusHandler#process` should scope `Commit.where(sha: ..., stack: { repository: matching org/repo })` instead of a bare `sha` lookup, and `verify_signature` should pass the resolved, verified organization down to handlers so they can enforce this scoping rather than re-parsing it from the same payload.

### Proof of Concept
1. Attacker registers/owns GitHub org `attacker-org`, which is added as a configured organization in this Shipit instance's `secrets.yml` (`github.attacker-org.webhook_secret = S`), giving the attacker a legitimate way to sign webhooks for `attacker-org` (e.g., by triggering real GitHub events on their own repo, or directly if they control the secret).
2. Attacker identifies a target commit SHA `X` belonging to `victim-org/victim-repo`, a stack tracked by the same Shipit instance with `continuous_deployment: true` and a CI-required safety gate, where commit `X` has not yet passed CI.
3. Attacker crafts a `status` webhook payload:
   ```json
   { "sha": "X", "state": "success", "context": "ci", "repository": {"owner": {"login": "attacker-org"}} }
   ```
   and signs it with `attacker-org`'s `webhook_secret` (`X-Hub-Signature: sha1=<hmac>`), setting `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org` from the payload, looks up `attacker-org`'s app, and successfully verifies the signature (`lib/shipit/github_app.rb#verify_webhook_signature`).
5. `StatusHandler#process` runs `Commit.where(sha: "X")`, finds the victim's commit (owned by `victim-org/victim-repo`), and calls `create_status_from_github!`, marking it as CI-passing — despite the attacker never having any access to `victim-org`.
6. If the victim stack is continuously deployed, the fabricated passing status can make the commit `deployable?`, leading to an unauthorized automatic deploy.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/stack.rb (L129-133)
```ruby
    def self.schedule_continuous_delivery
      not_archived.where(continuous_deployment: true).find_each do |stack|
        ContinuousDeliveryJob.perform_later(stack)
      end
    end
```

**File:** app/models/shipit/stack.rb (L161-172)
```ruby
    def build_deploy(until_commit, user, env: nil, force: false, allow_concurrency: force)
      since_commit = last_deployed_commit.presence || commits.first
      deploys.build(
        user_id: user.id,
        until_commit:,
        since_commit:,
        env: filter_deploy_envs(env.to_h),
        allow_concurrency:,
        ignored_safeties: force || !until_commit.deployable?,
        max_retries: retries_on_deploy
      )
    end
```
