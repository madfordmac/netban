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
The log file that records failed SSH login attempts is watched with a 
kernel-level iNotify event listener. When a failure is detected, the IP is used
as thekey in a redis database counting failed attempts. After each failed
attempt the key expiry is set to `timeout` seconds in the future. If that IP
has another failure before the timeout expires, the counter will increase and 
the timeout starts again. Once the counter reaches `limit` failures, the IP is 
banned for a full timeout interval.

### Net Modules
The net module provides a slower, but more proactive response to against groups
of IPs that are the source of multiple attacks. The Elasticsearch, Logstash, 
Kibana (ELK) centralized log storage system makes it easy to query a logs
across a large time interval to find these frequent fliers. Currently, the
code in this module only knows how to look up all of the IP blocks that belong
to a particular Autonomous System (AS). This could be abstracted in the future
to allow plugging in other lookups such as IP blocks for a country, for a
particular owner based on whois data, or fixed blocks of a particular size.
The following discussion tries to stay abstract, but uses AS blocks as the
example.

To do this we need to have 3 things:

1. A term that identifies the group to which a failure belongs. Using the 
logstash geoip filter ASN database, this would be the AS number for the network
to which the IP belongs. This is the `aggregate` value in the configuration.
1. A term that is unique for each entity in the group. The IP address is the
obvious choice here, but you could also do something like unique cities in a
country. This is the `cardinality` value in the config, as we count the number
of unique values, not total values.
1. A term by which we can discriminate between valid and invalid logins. For
logs produced by OpenSSH, there is a line logged for every auth attempt that 
begins with either "Accepted" or "Failed" and includes the IP address. A grok
filter can grab that word directly. The `filter-field` defines the field where
the value is stored, and the `filter-term` defines which value is bad.

Every `interval` (the next run is scheduled before processing the current one,
so this should only process slightly) we query the `elastic-index` index on the
Elasticsearch host at `elastic-host` for the `buckets` number of groups with 
the most unique values. If any of those buckets have more than `limit` unique
terms, we mark that group for blocking. The list of blocked groups from this
query is compared to the list of currently blocked hosts to determine if any
need adding or removing.

For groups that need adding, we make a network query to find the entire set of
IPs that belong to that group. We attempt to reconcile this against the set of
currently banned networks, but some errors still occur as IPv4 space is 
bought and sold, etc. Blocks that apper to need adding are added to the
firewall.

For groups that need removing, we use the saved list of nets that was looked
up when adding the group. We attempt to reconcile the group's space against
the currently banned space and remove all blocks for the group's space.

## Required Firewall Setup
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