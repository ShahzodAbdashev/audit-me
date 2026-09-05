"""Integration tests for the audit_logging pipeline (Agent A6).

Two tiers, same acceptance criteria, same numbering:

``test_acceptance_local.py``
    Tier 2. Runs anywhere. Asserts against the real ``FileSink`` JSONL output,
    fed through an in-process Elasticsearch double that applies the *actual*
    ``infra/elasticsearch/template-apiaudit.json`` mapping rules.

``test_acceptance_es.py``
    Tier 1. Marked ``integration``; needs the ``docker-compose.test.yml`` stack
    (Elasticsearch 8.x + Filebeat 8.x). Asserts against Elasticsearch itself,
    so it also covers Filebeat's ndjson decoding and the data-stream routing.
"""
