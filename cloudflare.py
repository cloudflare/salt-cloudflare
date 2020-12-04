# -*- coding: utf-8 -*-
'''
Manage Cloudflare zone records
==============================
This state allows to manage records of a particulare Cloudflare zone. It adds
missing records, removes extra records and updates existing records.

Updates are grouped by domain name and executed in the order that minimizes
the risk of downtime. Changes are also cheched for sanity before applying.

Remove comes first for scenarios where you change A to CNAME and similar.
.. code-block:: yaml
    example.com:
      cloudflare.manage_zone_records:
        - zone: {{ pillar["cloudflare_zones"]["example.com"]|yaml }}

Don't forget to use `yaml` filter, otherwise things get escaped twice.

Zone data will look like this:

.. code-block:: yaml
    cloudflare_zones:
      example.com:
        auth_email: ivan@example.com
        auth_key: |
          -----BEGIN PGP MESSAGE-----
          Comment: GPGTools - https://gpgtools.org

          PGP encrypted auth_key goes here.
          -----END PGP MESSAGE-----
        zone_id: 0101deadbeefdeadbeefdeadbeefdead
        records:
          - name: ivan.example.com
            content: 93.184.216.34
            proxied: true

Each record can have the following fields:

* `name`         - domain name (including zone)
* `content`      - value of the record
* `type`         - type of the record: A, AAAA, SRV, etc (A by default)
* `proxied`      - whether zone should be proxied (false by default)
* `ttl`          - TTL of the record, 1 means auto" (1 by default)
* `salt_managed` - Whether Salt should manage the record, or skip it (True by default)
* `priority`     - The priority of the record. Only valid (and required) for MX records

Reference: https://api.cloudflare.com/#dns-records-for-a-zone-properties

In addition to `records`, it's also possible to provide `exclude` key
with the list of regular expressions that will mark records that are
managed externally.

This state supports test mode. It makes sense to run it only on one node.
'''

from collections import namedtuple

import re
import json
import yaml
import requests
import logging
import salt.exceptions


logger = logging.getLogger(__name__)


def manage_zone_records(name, zone):
    managed = Zone(name, zone)

    try:
        managed.sanity_check()
    except salt.exceptions.SaltInvocationError as err:
        return {
            "name": name,
            "changes": {},
            "result": False,
            "comment": "{0}".format(err)
        }

    diff = managed.diff()

    result = {"name": name, "changes": _changes(diff), "result": None}

    if len(diff) == 0:
        result["comment"] = "The state of {0} ({1}) is up to date.".format(
            name, zone["zone_id"]
        )
        result["changes"] = {}
        result["result"] = None if __opts__["test"] == True else True
        return result

    if __opts__["test"] == True:
        result[
            "comment"
        ] = "The state of {0} ({1}) will be changed ({2} changes).".format(
            name, zone["zone_id"], len(diff)
        )
        result["pchanges"] = result["changes"]
        return result

    managed.apply(diff)

    result["comment"] = "The state of {0} ({1}) was changed ({2} changes).".format(
        name, zone["zone_id"], len(diff)
    )
    result["result"] = True

    return result


def _changes(diff):
    changes = {}
    actions = map(lambda op: "{0} {1}".format(op["action"], str(op["record"])), diff)
    if actions:
        changes['diff'] = "\n".join(actions)
    return changes

def validate_record(record):
    if "name" not in record:
        raise salt.exceptions.SaltInvocationError("'name' is required")
    if "content" not in record:
        raise salt.exceptions.SaltInvocationError("Required field 'content' is missing for entry <{0}>".format(record["name"]))
    if "type" in record and record["type"] == "MX" and "priority" not in record:
        raise salt.exceptions.SaltInvocationError("Required field 'priority' is missing for MX entry <{0}>".format(record["name"]))

def record_from_dict(record):
    record.setdefault("type", "A")
    record.setdefault("proxied", False)
    record.setdefault("id", None)
    record.setdefault("ttl", 1)
    record.setdefault("salt_managed", True)
    priority = record["priority"] if record["type"] == "MX" else None
    return Record(
        record["id"],
        record["type"],
        record["name"],
        record["content"],
        priority,
        record["proxied"],
        record["ttl"],
        record["salt_managed"],
    )


class Record(
    namedtuple(
        "Record", ("id", "type", "name", "content", "priority", "proxied", "ttl", "salt_managed")
    )
):
    def pure(self):
        return Record(
            None,
            self.type,
            self.name,
            self.content,
            self.priority,
            self.proxied,
            self.ttl,
            self.salt_managed,
        )

    """
    Cloudflare API expects `data` attribute when you add SRV records
    instead of `content`. This method synthesizes `data` from `content`.
    """

    def data(self):
        if self.type == "SRV":
            service, proto, name = self.name.split(".", 2)
            parts = self.content.split("\t")
            if len(parts) == 3:
                # record should look like this: "priority weight port target"
                # cloudflare returns: "weight port target"
                priority = 10
                weight, port, target = parts
            else:
                priority, weight, port, target = parts
            return {
                "service": service,
                "proto": proto,
                "name": name,
                "priority": int(priority),
                "weight": int(weight),
                "port": int(port),
                "target": target,
            }
        if self.type == "CAA":
            parts = self.content.split(" ")
            flags, tag, value = parts
            return {
                "name": self.name,
                "flags": int(flags),
                "tag": tag,
                "value": value[1:-1],
            }

    def __str__(self):
        ttl_str = 'auto' if self.ttl == 1 else '{0}s'.format(self.ttl)
        priority_string = 'priority: {0}, '.format(self.priority) if self.type == "MX" else ''
        return "{0} {1} -> '{2}' (proxied: {3}, ttl: {4})".format(
            self.type, self.name, self.content, priority_string, str(self.proxied).lower(), ttl_str
        )

    def json(self):
        dict = {
            "type": self.type,
            "name": self.name,
            "content": self.content,
            "proxied": self.proxied,
            "data": self.data(),
            "ttl": self.ttl,
        }
        if self.type == "MX":
            dict["priority"] = self.priority
        return dict


class Zone(object):

    ZONES_URI_TEMPLATE = "https://api.cloudflare.com/client/v4/zones/{zone_id}"
    RECORDS_URI_TEMPLATE = "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?page={page}&per_page=50"

    ADD_RECORD_URI_TEMPLATE = (
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    )
    REMOVE_RECORD_URI_TEMPLATE = (
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    )
    UPDATE_RECORD_URI_TEMPLATE = (
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    )

    ACTION_ADD = "add"
    ACTION_REMOVE = "remove"
    ACTION_UPDATE = "update"

    SPECIAL_APPLY_ORDER = {ACTION_REMOVE: 0, ACTION_ADD: 1, ACTION_UPDATE: 2}

    REGULAR_APPLY_ORDER = {ACTION_ADD: 0, ACTION_UPDATE: 1, ACTION_REMOVE: 2}

    def __init__(self, name, zone):
        self.name = name
        self.api_token = zone.get("api_token", None)
        self.auth_email = zone.get("auth_email", None)
        self.auth_key = zone.get("auth_key", None)
        self.zone_id = zone["zone_id"]
        self.records = zone["records"]
        self.exclude = zone.get('exclude', [])
        
        if not self.api_token and not (self.auth_email and self.auth_key):
            raise Exception("Either api_token or auth_email and auth_key must be provided")

    def _request(self, uri, method="GET", json=None):
        if self.api_token:
            headers = {"Authorization": "Bearer {0}".format(self.api_token)}
        else:
            headers = {"X-Auth-Email": self.auth_email, "X-Auth-Key": self.auth_key}

        logger.info("Sending request: {0} {1} data: {2}".format(method, uri, json))

        if method == "GET":
            resp = requests.get(uri, headers=headers)
        elif method == "POST":
            resp = requests.post(uri, headers=headers, json=json)
        elif method == "PUT":
            resp = requests.put(uri, headers=headers, json=json)
        elif method == "DELETE":
            resp = requests.delete(uri, headers=headers)
        else:
            raise Exception("Unknown request method: {0}".format(method))

        if not resp.ok:
            raise Exception(
                "Got HTTP code {0}: {1}".format(resp.status_code, resp.text)
            )

        return resp.json()

    def _add_record(self, record):
        self._request(
            self.ADD_RECORD_URI_TEMPLATE.format(zone_id=self.zone_id),
            method="POST",
            json=record.json(),
        )

    def _remove_record(self, record):
        self._request(
            self.REMOVE_RECORD_URI_TEMPLATE.format(
                zone_id=self.zone_id, record_id=record.id
            ),
            method="DELETE",
        )

    def _update_record(self, record):
        self._request(
            self.UPDATE_RECORD_URI_TEMPLATE.format(
                zone_id=self.zone_id, record_id=record.id
            ),
            method="PUT",
            json=record.json(),
        )

    def sanity_check(self):
        found = self._request(self.ZONES_URI_TEMPLATE.format(zone_id=self.zone_id))

        if self.name != found["result"]["name"]:
            raise Exception(
                "Zone name does not match: {0} != {1}".format(
                    self.name, found["result"]["name"]
                )
            )

        As = set()
        CNAMEs = set()

        for record in self.desired():
            if (
                not record.name.endswith("." + self.name)
                and not record.name == self.name
            ):
                raise Exception(
                    "Record {0} does not belong to zone {1}".format(
                        record.name, self.name
                    )
                )

            if record.ttl != 1 and record.ttl < 120:
                raise Exception(
                    "Record {0} has invalid TTL: {1}".format(record.name, record.ttl)
                )

            if record.ttl != 1 and record.proxied:
                raise Exception(
                    "Record {0} has TTL set, but TTL for proxied records is managed by Cloudflare".format(
                        record.name
                    )
                )

            try:
                record.data()
            except Exception as e:
                raise Exception(
                    "Record {0} cannot synthesize data from content: {1}".format(
                        str(record), e
                    )
                )

            if record.type in ("A", "AAAA"):
                As.add(record.name)
                if record.name in CNAMEs:
                    raise Exception(
                        "Record {0} has both A/AAAA and CNAME records".format(
                            record.name
                        )
                    )

            if record.type in ("CNAME",):
                if record.name in CNAMEs:
                    raise Exception(
                        "Record {0} has serveral CNAME records".format(record.name)
                    )
                CNAMEs.add(record.name)
                if record.name in As:
                    raise Exception(
                        "Record {0} has both A/AAAA and CNAME records".format(
                            record.name
                        )
                    )

    def existing(self):
        records = {}

        page = 1
        while True:
            found = self._request(
                self.RECORDS_URI_TEMPLATE.format(zone_id=self.zone_id, page=page)
            )

            for record_dict in found["result"]:
                record = record_from_dict(record_dict)
                excluded = False
                for pattern in self.exclude:
                    if re.match(pattern, record.name):
                        excluded = True
                        break
                if not excluded:
                    records[record_dict["id"]] = record

            current_page = found["result_info"]["page"]
            total_pages = found["result_info"]["total_pages"]
            if current_page == total_pages or total_pages == 0:
                break

            page += 1

        return records.values()

    def desired(self):
        for record in self.records:
            validate_record(record)
        return map(lambda record: record_from_dict(record.copy()), self.records)

    def diff(self):
        existing_tuples = {
            (record.type, record.name, record.content, record.salt_managed): record
            for record in self.existing()
        }
        desired_tuples = {
            (record.type, record.name, record.content, record.salt_managed): record
            for record in self.desired()
        }
        desired_salt_managed = {
            record.name: record.salt_managed for record in self.desired()
        }

        changes = []

        for key in set(desired_tuples).difference(existing_tuples):
            if not desired_tuples[key].salt_managed:
                continue
            changes.append({"action": self.ACTION_ADD, "record": desired_tuples[key]})

        for key in set(existing_tuples).difference(desired_tuples):
            if key[1] in desired_salt_managed and desired_salt_managed[key[1]] == False:
                continue
            changes.append(
                {"action": self.ACTION_REMOVE, "record": existing_tuples[key]}
            )

        for key in set(existing_tuples).intersection(desired_tuples):
            if (
                existing_tuples[key].pure() == desired_tuples[key]
                or not desired_tuples[key].salt_managed
            ):
                continue
            changes.append(
                {
                    "action": self.ACTION_UPDATE,
                    "record": Record(
                        existing_tuples[key].id,
                        desired_tuples[key].type,
                        desired_tuples[key].name,
                        desired_tuples[key].content,
                        priority=desired_tuples[key].priority,
                        proxied=desired_tuples[key].proxied,
                        ttl=desired_tuples[key].ttl,
                        salt_managed=True,
                    ),
                }
            )

        return self._order(changes)

    def _order(self, diff):
        groups = {"primary": {}, "rest": {}}

        for op in diff:
            group = "rest"
            if op["record"].type in ("A", "AAAA", "CNAME"):
                group = "primary"
            if op["record"].name not in groups[group]:
                groups[group][op["record"].name] = []
            groups[group][op["record"].name].append(op)

        result = []

        def append_in_order(ops, order):
            for op in sorted(ops, key=lambda op: order[op["action"]]):
                result.append(op)

        for name, ops in groups["primary"].items():
            if any(op["record"].type == "CNAME" for op in ops):
                # need to remove before adding
                append_in_order(ops, self.SPECIAL_APPLY_ORDER)
            else:
                # nothing special about these records
                append_in_order(ops, self.REGULAR_APPLY_ORDER)

        for name, ops in groups["rest"].items():
            append_in_order(ops, self.REGULAR_APPLY_ORDER)

        return result

    def apply(self, diff):
        for op in diff:
            if op["action"] == self.ACTION_ADD:
                self._add_record(op["record"])
            elif op["action"] == self.ACTION_REMOVE:
                self._remove_record(op["record"])
            elif op["action"] == self.ACTION_UPDATE:
                self._update_record(op["record"])
            else:
                raise Exception(
                    "Unknown action {0} for record {1}", op["action"], str(op["record"])
                )
