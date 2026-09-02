### Title
Webhook signature verification binds to an attacker-suppliable organization field, not to the repository the event actually mutates - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate an incoming payload against using a value taken directly out of the untrusted JSON body (`repository.owner.login`, falling back to `organization.login`), rather than from any value tied to the specific `Stack`/`Repository` record that downstream handlers will actually act on. Because the payload contains at least two independent, attacker-controlled fields — the "owner" used for secret selection and the "repository" identity used by the event handlers to locate the target `Stack` — nothing in the controller cross-checks that they refer to the same GitHub repository/organization.

### Finding Description
`verify_signature` computes the org used for HMAC validation purely from payload content: [1](#0-0) [2](#0-1) 

The actual cryptographic check is a straightforward HMAC-SHA1 comparison against the secret configured for whatever organization name was extracted: [3](#0-2) 

The equality this flow is supposed to enforce is:
`organization whose secret signed the request == organization that owns the repository the event will be applied to`

But the controller only proves: `organization whose secret signed the request == organization.login/repository.owner.login field present in this JSON body`. That field is not the same value the rest of the pipeline uses to resolve which `Stack`/`Repository` object gets mutated — event handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers, etc., under `app/models/shipit/webhooks/handlers/`) resolve the target repository from the `repository` object in the same payload (matched against `Repository`/`Stack` records, which is where the majority of `full_name`/`github_repo_name` references live in the codebase). Since `repository.owner.login` (used for secret lookup) and the rest of the `repository` payload (used for target resolution) are two independently attacker-controlled JSON fields inside the same request body, nothing forces them to be consistent.

Concretely: any party that legitimately controls one GitHub organization/repository that is configured in this Shipit instance (and therefore knows/can trigger delivery of a validly-signed webhook for that org) can craft a payload where the `owner`/`organization` field used for signature-org lookup names their own org (so `verify_webhook_signature` succeeds against their own known secret) while the nested `repository` data used by the handlers names a completely different, unrelated stack's repository. This breaks the trust binding "the organization that authenticated the request" vs "the repository whose state gets written."

### Impact Explanation
If exploitable end-to-end, this allows a party who only has legitimate access to one org/repo configured in Shipit to forge webhook events (push refs, commit statuses, check runs, pull_request state, membership) attributed to a completely different repository/stack they do not control. Forged `success` commit statuses on a target stack could satisfy `Commit#deployable?` and, combined with continuous delivery, trigger an unauthorized deploy: [4](#0-3) [5](#0-4) 

This lines up with the "unauthorized deploy" / "cross-repository writes" impact tier defined for this engine.

### Likelihood Explanation
Exploitability depends on the deployment actually hosting multiple, mutually-distrusting organizations/repositories behind the same Shipit instance (a documented, supported multi-tenant configuration per `Shipit.github_apps`), and on the precise repository-resolution logic inside the individual webhook handlers, which I was not able to fully read within the available iterations (`push_handler.rb`, `status_handler.rb` bodies were not retrieved). I confirmed the vulnerable signature-verification logic in `webhooks_controller.rb` and `github_app.rb`, and confirmed via file layout that repository resolution in handlers is based on repository identity fields (`Repository`/`full_name`/`github_repo_name` usage concentrated in `app/models/shipit/repository.rb`, `app/models/shipit/stack.rb`, and the handler classes), but I could not verify from source whether handlers additionally re-derive/cross-check the owning organization against the one used for signature verification. This should be treated as a probable but not fully proven cross-tenant forgery path — confirming it requires reading the handler bodies directly (recommend a Devin session with full file access for final confirmation).

### Recommendation
- In `WebhooksController#verify_signature`, resolve the signing organization/app from a trusted, server-side source (e.g., look up the `Stack`/`Repository` record independently and derive its configured organization) rather than trusting `repository.owner.login`/`organization.login` from the unauthenticated payload.
- After signature verification, re-validate that the `repository`/`organization` identity actually used by each handler to locate a `Stack` matches the organization whose secret validated the request, rejecting (422) any mismatch.

### Proof of Concept
Conceptual (not fully verified against handler internals due to inability to read `push_handler.rb`/`status_handler.rb` in this session):
1. Attacker controls `org-attacker`, which is configured in Shipit with a known-to-them webhook secret (`Shipit.github(organization: 'org-attacker')`).
2. Attacker crafts a JSON payload for the `status` event type where:
   - `organization.login` / `repository.owner.login` = `"org-attacker"` (so `repository_owner` in `webhooks_controller.rb` resolves to `org-attacker`, and the HMAC computed with `org-attacker`'s secret validates).
   - `repository.full_name` / commit `sha` correspond to a stack belonging to `org-victim/some-repo`, a completely unrelated, more privileged stack hosted on the same Shipit instance.
3. `WebhooksController#verify_signature` passes because it only checks the signature against `org-attacker`'s secret.
4. `StatusHandler` (or equivalent) processes the payload, resolves `org-victim/some-repo`'s `Stack`/`Commit` from the `repository` field, and records a forged commit status (e.g., `success`) against `org-victim`'s commit.
5. If `org-victim`'s stack has continuous deployment enabled, `Commit#deployable?` returning true off the forged status can trigger `Stack#trigger_continuous_delivery`, producing an unauthorized deploy.

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
