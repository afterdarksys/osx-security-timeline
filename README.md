# macOS Security Timeline (sectimeline)

A local-only service that builds a security timeline of your Mac, then lets you ask questions like "What changed right before my mic turned on?"

**Time Machine for Security**

## The Problem

macOS logs are:
- Fragmented across dozens of sources
- Unreadable without specialized knowledge
- Missing correlation between events
- No way to ask "what changed?"

When you discover a compromise, you need to know:
- What was installed recently?
- What permissions were granted?
- What network connections were made?
- What changed before the incident?

## Solution

`sectimeline` collects security-relevant events into a queryable timeline:

```bash
$ sectimeline query "What changed yesterday?"

Found 47 events since 2026-01-16 00:00

  2026-01-16 09:15:22 [app_install] Installed Slack 4.35.126
  2026-01-16 09:16:01 [permission_grant] Slack granted microphone access
  2026-01-16 11:23:45 [launch_agent] Launch item modified: com.slack.SlackHelper
  2026-01-16 14:02:33 [permission_use] Camera accessed by zoom.us
  ...
```

## Features

- **Comprehensive collection** - App installs, permissions, binaries, network, USB, launch items
- **Natural language queries** - Ask questions in plain English
- **Time-based filtering** - "Show me what happened last week"
- **Event correlation** - See related events together
- **Risk scoring** - Highlight suspicious activity
- **Local only** - No cloud, no telemetry, privacy-preserving
- **HTTP API** - Integration with dashboards

## Installation

```bash
make build
sudo make install
```

## Quick Start

```bash
# Collect events from last 24 hours
sectimeline collect

# Show recent timeline
sectimeline show

# Ask a question
sectimeline query "What was installed this week?"

# Start background collection
sectimeline daemon start

# View summary
sectimeline summary
```

## Usage

### Show Timeline

```bash
# Last 24 hours (default)
sectimeline show

# Last 7 days
sectimeline show --since 7d

# Today only
sectimeline show --since today

# Filter by type
sectimeline show --type app_install

# Limit results
sectimeline show --limit 100
```

### Query Timeline

```bash
# Natural language queries
sectimeline query "What changed today?"
sectimeline query "Show permission changes"
sectimeline query "What happened last week?"
sectimeline query "What was installed yesterday?"
sectimeline query "Show USB events"
sectimeline query "What network activity occurred?"
```

### Manual Collection

```bash
# Collect last 24 hours
sectimeline collect

# Collect last 7 days
sectimeline collect --since 7d

# Collect last hour
sectimeline collect --since 1h
```

### Daemon Mode

```bash
# Start in foreground (for testing)
sectimeline daemon start -f

# Start as background daemon
sectimeline daemon start

# Check status
sectimeline daemon status

# Stop daemon
sectimeline daemon stop
```

### Data Management

```bash
# Export to file
sectimeline export backup.json

# Import from file
sectimeline import backup.json

# Prune old events (default: 90 days)
sectimeline prune

# Keep only last 30 days
sectimeline prune --days 30
```

## Event Types

| Type | Description |
|------|-------------|
| `app_install` | Application installed |
| `app_uninstall` | Application removed |
| `app_launch` | Application launched |
| `permission_grant` | Permission granted (camera, mic, etc.) |
| `permission_use` | Permission used |
| `new_binary` | New executable appeared |
| `binary_modified` | Existing binary changed |
| `network_access` | Network connection made |
| `usb_insert` | USB device connected |
| `usb_remove` | USB device disconnected |
| `login_item` | Login item added/modified |
| `launch_agent` | LaunchAgent added/modified |
| `launch_daemon` | LaunchDaemon added/modified |
| `system_boot` | System started |
| `user_login` | User logged in |
| `user_logout` | User logged out |
| `firewall_change` | Firewall settings changed |
| `gatekeeper` | Gatekeeper event |
| `xprotect` | XProtect (malware) event |
| `system_update` | System update installed |

## Configuration

Config file: `~/.config/sectimeline/config.yaml`

```yaml
# Data storage location
data_dir: ~/.config/sectimeline/data

# Collection interval when daemon is running
collect_interval: 5m

# How long to keep events
retention_days: 90

# HTTP API
http_port: 9012
enable_http: true

# Logging
log_level: info
```

## HTTP API

When the daemon is running, it exposes an HTTP API (default port 9012):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/info` | GET | Version and event count |
| `/events` | GET | Get events (params: since, until) |
| `/timeline` | GET | Full timeline with summary |
| `/query?q=...` | GET | Natural language query |
| `/summary` | GET | Timeline summary statistics |
| `/collect` | POST | Trigger immediate collection |

## Data Sources

### Unified Log
- TCC (permissions) events
- Gatekeeper assessments
- XProtect detections
- Login/logout events

### Install History
- `/Library/Receipts/InstallHistory.plist`

### TCC Database
- Permission grants and modifications

### Launch Items
- `~/Library/LaunchAgents`
- `/Library/LaunchAgents`
- `/Library/LaunchDaemons`

### System Preferences
- Security-related preference changes

## Example Queries

```bash
# Security incidents
sectimeline query "What changed before my camera turned on?"

# Software audit
sectimeline query "What was installed last month?"

# Permission review
sectimeline query "Show all permission grants"

# Persistence check
sectimeline query "What launch agents were added?"

# Time-based
sectimeline query "What happened between 9am and 5pm?"
```

## Integration

### With Other ADS Tools

```bash
# Start all monitoring services
sectimeline daemon start &
pam daemon start &
scfw daemon start &

# Query timeline for suspicious activity
sectimeline query "What changed in the last hour?" --json | jq
```

### SIEM Export

```bash
# Export for Splunk/Elastic
sectimeline export --format json events.json

# Stream to SIEM
sectimeline show --json | your-siem-forwarder
```

## Technical Details

### Requirements
- macOS 10.15+ (Catalina or later)
- Some events require elevated privileges

### Limitations
- USB events require additional permissions
- Some unified log queries need root access
- TCC database may require Full Disk Access

### Storage
- Events stored as JSON files by date
- Automatic deduplication by event ID
- Configurable retention period

## Use Cases

### Incident Response
"Reconstruct what happened before the breach was detected."

### Compliance Auditing
"Document all software installations and permission changes."

### Personal Security
"Know what's happening on your Mac."

### Malware Analysis
"Track what a suspicious app did after installation."

## Roadmap

- [ ] GUI timeline viewer
- [ ] Real-time notifications
- [ ] Machine learning anomaly detection
- [ ] Cross-device sync (encrypted)
- [ ] Integration with threat intel feeds
- [ ] Automatic incident reports

## License

MIT License

## Related Projects

- **osx-syscall-firewall** - Per-binary system call policies
- **osx-permission-abuse-monitor** - Post-grant permission monitoring
- **osx-explain-a-bin** - Binary trust reports

---

**Part of the AfterDark Security macOS Suite**
