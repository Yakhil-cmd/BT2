### Title
Webhook signature verification is bound to an attacker-chosen `repository.owner.login`, not to the repository/commit actually mutated - forged CI status and sync events across organizations - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to validate `X-Hub-Signature` from a field taken out of the *same unverified JSON body* it is about to verify (`repository.owner.login`, with `organization.login` as fallback), rather than from any value tied to the specific repository/commit that downstream handlers then act on. In a multi-organization Shipit deployment, an attacker who legitimately controls one configured GitHub organization (and therefore knows that organization's `webhook_secret`) can craft a webhook body whose `repository.owner.login` matches their own org (so the signature check passes) while other payload fields (`repository.full_name`, `sha`, etc.) reference a completely different, victim-owned repository or commit.

### Finding Description
`verify_signature` resolves the signing secret before any part of the payload has been authenticated: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`verify_webhook_signature` then HMAC-validates the *entire raw body* against the secret for whatever organization `repository_owner` happened to name: [3](#0-2) 

Because the attacker fully controls the raw JSON body, they can set `repository.owner.login` to their own organization (whose secret they know, since they administer that org's GitHub App installation as documented for multi-org setups: [4](#0-3) ) while setting every other field — `repository.full_name`, `sha`, `check_suite.head_sha`, `ref` — to reference a victim organization's repository/commit. The signature check only proves "this body was signed with org A's secret"; it never proves "org A owns the repository/commit this body claims to describe."

Downstream handlers then trust those unauthenticated fields to decide what to mutate:
- `Handler#repository_name` reads `payload.dig('repository', 'full_name')` to locate `Repository`/`Stack` records, entirely independent of the org used for signature verification: [5](#0-4) 
- `StatusHandler#process` is even weaker: it looks up commits by `sha` alone, globally, with no repository scoping at all: [6](#0-5) 
- `PushHandler` and `CheckSuiteHandler` similarly key off `Repository.from_github_repo_name(repository_name)` from the same untrusted body: [7](#0-6) [8](#0-7) 

This is the same trust-binding gap as the ERC4337 report: the value the "signature" is checked against (organization A) is not cryptographically or logically bound to the value that determines what gets written (repository/commit B). Exactly as a salt < 2^96 let an attacker swap in their own owner while still deploying to the victim's precomputed address, a `repository.owner.login` chosen to match a secret the attacker controls lets them swap in an arbitrary victim `full_name`/`sha` while still passing signature verification.

### Impact Explanation
An attacker who controls (or has been granted) one GitHub organization wired into a multi-org Shipit instance can forge signed webhook deliveries that are attributed to that org's secret but whose content addresses any other org's repositories and commits tracked by the same Shipit instance. Most notably, via `StatusHandler`, they can post a fabricated successful commit status (`state: "success"`) for any commit `sha` in the victim's repository, without needing that repository's own webhook secret at all. Shipit's deployability/merge-queue gating typically relies on such CI status records to decide whether a commit is safe to merge or deploy, so this can be used to make a malicious or unreviewed commit appear "green" and eligible for an unauthorized deploy or merge. It can also be used to spoof `push` and `check_suite` events, forcing spurious syncs or check-run refreshes against a repository the attacker doesn't own.

### Likelihood Explanation
This requires the Shipit instance to be configured with more than one GitHub App/organization (the documented "Using Multiple Github Applications" mode) and for the attacker to be a legitimate, unprivileged member/admin of at least one of those configured organizations — a realistic scenario for shared internal Shipit deployments serving multiple teams/orgs. No Shipit session, `ApiClient` token, or the victim organization's `webhook_secret` is needed; the attacker only needs the secret of an organization they already administer, which is not a privilege escalation within Shipit's own trust model and does not fall under the excluded "requires webhook_secret" case since it's their own org's secret, not the victim's.

### Recommendation
Do not let any part of the unauthenticated payload select the verification key. Either (a) route webhooks per-organization (e.g., `/webhooks/:organization`) so the URL/route — not payload content — determines which secret is used, or (b) after successful signature verification, re-derive and enforce that the organization whose secret validated the request equals the owner encoded in every repository/commit reference the handler is about to act on (`repository.full_name`'s owner segment, and for `StatusHandler`, scope the `Commit` lookup through `Stack`/`Repository` owned by the verified organization instead of a bare global `sha` lookup).

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` (attacker-administered, webhook secret known to attacker) and `orgB` (victim, has a Stack tracking commit `deadbeef`).
2. Attacker crafts a `status` webhook JSON body:
   ```json
   {
     "sha": "deadbeef",
     "state": "success",
     "context": "ci/attacker-forged",
     "repository": { "owner": { "login": "orgA" }, "full_name": "orgA/whatever" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(orgA_webhook_secret, body)` and POSTs to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "orgA")` and validates successfully against `orgA`'s secret.
5. `StatusHandler#process` runs `Commit.where(sha: "deadbeef")`, which matches the victim's `orgB` commit and records a forged "success" status on it, with no cross-check that `orgA` owns that commit or repository.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
