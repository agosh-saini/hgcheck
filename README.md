# hgcheck

`hgcheck` (Homograph Guard) is a CLI tool designed to detect Unicode homograph attacks, confusing characters, mixed scripts, and hidden Bidi control characters. It can scan text strings or wrap commands to ensure arguments are safe before execution.

## Features

- **Homograph Detection**: Identifies characters that look identical or similar but have different Unicode code points.
- **Mixed Script Detection**: Warns when strings contain characters from multiple scripts (e.g., Latin mixed with Cyrillic), which is a common phishing technique.
- **Bidi & Hidden Character Check**: Detects dangerous bidirectional control characters or invisible characters that can alter how text is rendered vs. how it is interpreted.
- **Normalization Checks**: alerts on NFKC or Skeleton normalization changes.
- **Command wrapper**: The `run` command scans arguments for risks before executing the command.

## Installation

```bash
cargo install --path .
```

## Usage

### Scanning Text

Scan a string for potential issues:

```bash
hgcheck scan "googIe.com"
```

Output (JSON by default):

```json
{
  "sections": [ ... ],
  "findings": [ ... ],
  "decision": "Warn"
}
```

Use `--human` for readable output:

```bash
hgcheck scan "googIe.com" --human
```

### Safe Execution Wrapper

Wrap any command to scan its arguments before running:

```bash
hgcheck run -- echo "SuspisiousString"
```

If high-risk characters are found, `hg` will block execution. If warnings are found, it may ask for confirmation.

To force execution despite findings:

```bash
hgcheck run --allow -- echo "SuspisiousString"
```

## License

MIT License. See [LICENSE](LICENSE) for details.
