# netban
Brute force login detection/prevention across managed public nodes using redis
and Elastic for analytics.

## How does it work?
The local and network (AS) bans have entirely separate mechanics. Together they
protect against immediate and persistent threats.

### Local Module
The local module provides rapid-response protection against active attacks to
the local system. This module is local-only to provide the fastest, most
resilient defense against a single active attacker.
The log file that records failed SSH login attempts is watched with a kernel-
level iNotify event listener. When a failure is detected, the IP is used as the
key in a redis database counting failed attempts. After each failed attempt the
key expiry is set to `timeout` seconds in the future. If that IP has another
failure before the timeout expires, the counter will increase and the timeout
starts again. Once the counter reaches `limit` failures, the IP is banned for
a full timeout interval.

### Net Modules
The net module provides a slower, but more proactive response to against remote
networks that are the source of multiple attacks.

> More text is needed to describe this module. The abstraction provided by the
configuration makes this somewhat tricky to describe in general terms.

## Required Setup
Create two empty named sets in your nft configuration and insert them at an
appropriate point to drop traffic. This is probably after rules to allow
related/established traffic (use MaxAuthTries in your sshd_config to mitigate
repeated attempts on the same connection,) but clearly must be before the rule
to allow port 22. The set name parameters in the config should be set to the
full `<family> <table> <set>` name of the table. Ex., `inet filter netban`.
Both tables must be of type `ipv4_addr`. The network block set must have the
`interval` flag.

An example correct set definition is
```
table inet filter {
    set localban {
        type ipv4_addr
    }

    set netban {
        type ipv4_addr
        flags interval
    }

    chain input {
        type filter hook input priority filter; policy drop;
        ct state vmap { invalid: drop, established: accept, related: accept }
        ip saddr @localban drop
        ip saddr @netban drop
        tcp dport 22 accept
    }
}
```