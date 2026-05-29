# Policy

## 1. Policy Format

Use **TOML** for human readability.

Policy file location (encrypted at rest):

```
~/.aisudo/private/policy.enc
```

The daemon exposes filtered explanations, **not** raw policy, unless the human approves.

---

## 2. Example Policy

```toml
[defaults]
unknown = "ask"

[[rules]]
name = "allow elixir tests"
app = "*"
action = "exec"
argv = ["mix", "test", "*"]
decision = "allow"
risk = "low"

[[rules]]
name = "allow elixir format"
app = "*"
action = "exec"
argv = ["mix", "format", "*"]
decision = "allow"
risk = "low"

[[rules]]
name = "ask package managers"
action = "exec"
argv_any_of = [
  ["npm", "*"],
  ["pnpm", "*"],
  ["yarn", "*"],
  ["pip", "*"],
  ["pip3", "*"]
]
decision = "ask"
risk = "high"

[[rules]]
name = "deny ssh private key access"
action_any_of = ["file-read", "file-write"]
path = "~/.ssh/**"
decision = "deny"
risk = "critical"

[[rules]]
name = "ask github token"
action = "secret"
resource = "GITHUB_TOKEN"
decision = "ask"
risk = "high"

[[rules]]
name = "deny sudo by default"
action = "exec"
argv = ["sudo", "*"]
decision = "deny"
risk = "critical"
```

---

## 3. Policy Decisions

```
allow
ask
deny
```

---

## 4. Risk Levels

```
low
medium
high
critical
```

---

## 5. Policy Proposals

Agents may **create** proposals. Agents must **not** directly edit active policy.

### Flow

```bash
# Agent creates a proposal
aisudo policy propose ./policy.proposed.toml

# Daemon creates proposal_01j...

# Human reviews the diff
aisudo policy diff proposal_01j...

# Output:
# + [[rules]]
# + name = "allow mix test for my_app"
# + app = "claude-code"
# + action = "exec"
# + argv = ["mix", "test", "*"]
# + cwd = "/Users/hernan/dev/my_app"
# + decision = "allow"
# + risk = "low"

# Human applies (requires approval)
aisudo policy apply proposal_01j...
```

---

## 6. Package Manager Risk Heuristics

MVP should include built-in high-risk classification for common package manager operations.

### 6.1 npm / pnpm / yarn

**High risk:**

```
npm install          pnpm install          yarn install
npm add              pnpm add
npm publish          pnpm publish
```

Reasons:

- Downloads untrusted code
- May execute lifecycle scripts
- May modify lockfiles
- May introduce transitive dependencies
- May read environment variables
- May run native build steps

**Safer variants** (still logged):

```bash
npm ci --ignore-scripts
pnpm install --frozen-lockfile --ignore-scripts
yarn install --immutable
```

### 6.2 pip

**High risk:**

```
pip install
pip install git+...
pip install http://...
pip install https://...
```

**Safer pattern:**

```bash
pip install --require-hashes -r requirements.txt
```

### 6.3 Global installs

**Critical or high risk:**

```
npm install -g       pnpm add -g
pip install --user   brew install
cargo install        curl | sh
wget | sh
```
