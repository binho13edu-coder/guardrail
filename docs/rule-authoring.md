# Creating GuardRail rules

GuardRail loads every `.yaml` and `.yml` file below the path passed with `--rules` (the default is `rules/`). Each file has a top-level `rules` list.

```yaml
rules:
  - name: "Human-readable policy name"
    description: "Explain the risk and its operational impact."
    pattern: "policy identifier or regular expression"
    type: "REGEX"
    severity: "HIGH"
    target_files: ["*.env"]
```

## Rule fields

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Unique, understandable policy name. |
| `description` | no | Risk explanation shown in the report. |
| `pattern` | yes | RE2 expression for `REGEX`, or a supported policy identifier for `CONFIG`. |
| `type` | no | `REGEX` (default) or `CONFIG`. |
| `severity` | yes | `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`. |
| `target_files` | CONFIG: yes | Filename glob(s), such as `Dockerfile`, `*.tf`, or `*.json`. |
| `match_keys` | JSON/YAML: optional | Exact configuration keys evaluated by a structured policy. |

## Regex rule

```yaml
- name: "Internal token"
  description: "A token in source control can be used outside its intended runtime."
  pattern: "(?i)internal_token\\s*=\\s*[A-Za-z0-9]{24,}"
  type: "REGEX"
  severity: "HIGH"
  target_files: ["*.env", "*.yaml"]
```

## Dockerfile policies

Use `CONFIG` and one of these policy identifiers: `docker.user-root`, `docker.mutable-tag`, or `docker.add`.

```yaml
- name: "Container uses root"
  description: "A compromised container receives unnecessary privileges."
  pattern: "docker.user-root"
  type: "CONFIG"
  severity: "HIGH"
  target_files: ["Dockerfile", "Dockerfile.*"]
```

## Terraform policies

Use `terraform.public-access` or `terraform.volume-encryption`. Terraform is parsed with HCL; comments and string literals are not mistaken for resource attributes.

```yaml
- name: "Public Terraform resource"
  description: "The resource may expose data or services to the internet."
  pattern: "terraform.public-access"
  type: "CONFIG"
  severity: "CRITICAL"
  target_files: ["*.tf"]
```

## JSON and YAML policies

`config.boolean-true` traverses parsed objects and arrays. It reports when a configured key has the boolean value `true`; text in comments or strings is not treated as a boolean.

```yaml
- name: "Public access in application configuration"
  description: "Public access can expose application data."
  pattern: "config.boolean-true"
  type: "CONFIG"
  severity: "HIGH"
  target_files: ["*.json", "*.yaml", "*.yml"]
  match_keys: ["allow_public_access", "public_access"]
```

## CI behavior

Use `--threshold` to make findings fail a pipeline: `critical` (default), `high`, `medium`, `low`, or `none`. Exit code `1` means that findings met the threshold; exit code `2` indicates an execution, parsing, or configuration error.

## SARIF output

Use `--format sarif` to emit SARIF 2.1.0. Each finding becomes a SARIF result with its rule ID, severity level, impact description, source file, and line number. This is the format consumed by GitHub Code Scanning and other security platforms.

```bash
guardrail scan . --format sarif --output guardrail.sarif --threshold none
```

`CRITICAL` and `HIGH` map to SARIF `error`, `MEDIUM` to `warning`, and `LOW` to `note`.
