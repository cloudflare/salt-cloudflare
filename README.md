# Cloudflare salt state

Cloudflare salt module allows you to manage zones on Cloudflare from salt.

## Installation

1. Copy `cloudflare.py` into `/srv/salt/_states` or do the equivalent if you
  use a different layout for `file_roots` on Salt master.

2. Sync state cache on the minion you plan to use for managing zones:

  ```
  salt-call saltutil.sync_states
  ```

### Managing DNS records

#### Obtaining credentials

Note that you can use a dedicated account with `DNS Administrator` permissions
to manage zone records if your account is a multi-user organization.

First of all, you have to obtain the Global API Key for the account:

* https://www.cloudflare.com/a/account/my-account

Then you need to get the zone identifier (Zone ID). You can find it on the main
page of Cloudflare dashboard:

* https://www.cloudflare.com/a/overview

#### Salt changes

Write the state like this (call it `cloudflare.sls`):

```yaml
example.com:
  cloudflare.manage_zone_records:
    - zone: {{ pillar["cloudflare_zones"]["example.com"]|yaml }}
```

Then add the following to the pillar (use your credentials and records):

```yaml
cloudflare_zones:
  example.com:
    auth_email: ivan@example.com
    auth_key: auth key goes here
    zone_id: 0101deadbeefdeadbeefdeadbeefdead
    records:
      - name: ivan.exmaple.com
        content: 93.184.216.34
        proxied: true
```

Each record can have the following fields:

* `name`         - domain name (including zone)
* `content`      - value of the record
* `type`         - type of the record: `A`, `AAAA`, `SRV`, etc (`A` by default)
* `proxied`      - whether zone should be proxied (`false` by default)
* `ttl`          - TTL of the record in seconds, `1` means auto" (`1` by default)
* `salt_managed` - whether the record will be managed by Salt (`true` by default)
* `priority`     - The priority of the record. Only valid (and required) for MX records

Reference: https://api.cloudflare.com/#dns-records-for-a-zone-properties

Use salt PGP renderer if you can to encrypt the auth key:

* https://docs.saltstack.com/en/latest/ref/renderers/all/salt.renderers.gpg.html

Run the state in dry run mode:

```
salt-call state.apply cloudflare test=true
```

Then, if you are happy with the changes, apply them:

```
salt-call state.apply cloudflare
```

After a short period of time your changes should propagate across the network.

## Copyright

* Copyright 2016 Cloudflare

## License

[MIT](LICENSE)
