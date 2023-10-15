# netban
Brute force login detection/prevention across managed public nodes using redis and Elastic for analytics

## Required Setup
Create an empty named set in your nft configuration and insert it an
appropriate point to drop traffic. This is probably after rules to allow
related/established traffic (use MaxAuthTries in your sshd_config to mitigate
repeated attempts on the same connection,) but clearly must be before the rule
to allow port 22. The set name parameter in the config should be set to the
full `<family> <table> <set>` name of the table. Ex., `inet filter ban`. This
table must be of type `ipv4_addr` and have the `interval` flag.

An example correct set definition is
```
table inet filter {
    set ban {
        type ipv4_addr
        flags interval
    }

    chain input {
        type filter hook input priority filter; policy drop;
        ct state vmap { invalid: drop, established: accept, related: accept }
        ip saddr @ban drop
    }
}
```