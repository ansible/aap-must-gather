#!/usr/bin/env python3
"""
Unit tests for the must-gather redaction script.

Run with: pytest tests/test_redactors.py -v
"""

import sys
from pathlib import Path

import pytest
import importlib.util
import importlib.machinery

_redact_path = str(Path(__file__).parent.parent / "collection-scripts" / "redact")
_loader = importlib.machinery.SourceFileLoader("redact", _redact_path)
spec = importlib.util.spec_from_loader("redact", _loader, origin=_redact_path)
redact_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redact_mod)

CertificateRedactor = redact_mod.CertificateRedactor
PasswordRedactor = redact_mod.PasswordRedactor
IPRedactor = redact_mod.IPRedactor
DomainRedactor = redact_mod.DomainRedactor
ConfigMapRedactor = redact_mod.ConfigMapRedactor
RedactorChain = redact_mod.RedactorChain
get_default_redactors = redact_mod.get_default_redactors


class TestCertificateRedactor:
    def setup_method(self):
        self.redactor = CertificateRedactor()

    def test_single_certificate(self):
        content = ("-----BEGIN CERTIFICATE-----\n"
                   "MIIDXTCCAkWgAwIBAgIJAKL0UG+mRaqg\n"
                   "-----END CERTIFICATE-----")
        result = self.redactor.redact(content)
        assert result.modified
        assert "[REDACTED]" in result.content
        assert "MIIDXTCCAkWg" not in result.content
        assert "-----BEGIN CERTIFICATE-----" in result.content
        assert "-----END CERTIFICATE-----" in result.content

    def test_multiple_certificates(self):
        content = ("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
                   "some text\n"
                   "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----")
        result = self.redactor.redact(content)
        assert result.modified
        assert result.redaction_count == 2
        assert "AAA" not in result.content
        assert "BBB" not in result.content

    def test_no_certificates(self):
        content = "just plain text with no certs"
        result = self.redactor.redact(content)
        assert not result.modified
        assert result.content == content

    def test_empty_content(self):
        result = self.redactor.redact("")
        assert not result.modified
        assert result.content == ""


class TestPasswordRedactor:
    def setup_method(self):
        self.redactor = PasswordRedactor()

    def test_env_var_password(self):
        result = self.redactor.redact("PASSWORD=mysecret123")
        assert result.modified
        assert "mysecret123" not in result.content
        assert "PASSWORD=[REDACTED]" in result.content

    def test_prefixed_token(self):
        result = self.redactor.redact("GITHUB_TOKEN=ghp_abc123xyz")
        assert result.modified
        assert "ghp_abc123xyz" not in result.content
        assert "GITHUB_TOKEN=[REDACTED]" in result.content

    def test_json_secret_key(self):
        content = '"SECRET_KEY": "my-super-secret-value"'
        result = self.redactor.redact(content)
        assert result.modified
        assert "my-super-secret-value" not in result.content
        assert '"SECRET_KEY": "[REDACTED]"' in result.content

    def test_yaml_api_key(self):
        content = "API_KEY: sk-1234567890abcdef"
        result = self.redactor.redact(content)
        assert result.modified
        assert "sk-1234567890abcdef" not in result.content
        assert "[REDACTED]" in result.content

    def test_django_superuser_password(self):
        content = "DJANGO_SUPERUSER_PASSWORD=admin123"
        result = self.redactor.redact(content)
        assert result.modified
        assert "admin123" not in result.content

    def test_high_entropy_token(self):
        token = "a" * 65
        content = f"something {token} else"
        result = self.redactor.redact(content)
        assert result.modified
        assert token not in result.content
        assert "[REDACTED_TOKEN]" in result.content

    def test_sha256_digest_preserved(self):
        content = "image: sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        result = self.redactor.redact(content)
        assert "sha256:abcdef" in result.content

    def test_short_values_not_caught_by_entropy(self):
        content = "LABEL=shortvalue"
        result = self.redactor.redact(content)
        assert "shortvalue" in result.content

    def test_kubernetes_pod_names_preserved(self):
        content = "pod/alexeym26-lightspeed-api-b9db49cb5-nz72d"
        result = self.redactor.redact(content)
        assert "alexeym26-lightspeed-api-b9db49cb5-nz72d" in result.content

    def test_kubernetes_yaml_name_value(self):
        content = ("    - name: PROVIDER_TOKEN\n"
                   "      value: sk-secret-token-123\n"
                   "    - name: NORMAL_VAR")
        result = self.redactor.redact(content)
        assert result.modified
        assert "sk-secret-token-123" not in result.content
        assert "name: PROVIDER_TOKEN" in result.content

    def test_json_name_value_pair(self):
        content = '{"name": "API_TOKEN", "value": "secret-abc"}'
        result = self.redactor.redact(content)
        assert result.modified
        assert "secret-abc" not in result.content
        assert '"name": "API_TOKEN"' in result.content

    def test_empty_content(self):
        result = self.redactor.redact("")
        assert not result.modified


class TestIPRedactor:
    def setup_method(self):
        self.redactor = IPRedactor()

    def test_internal_ip(self):
        result = self.redactor.redact("Server: 10.20.30.40")
        assert result.modified
        assert "10.20.30.40" not in result.content
        assert "10.REDACTED." in result.content

    def test_k8s_ip(self):
        result = self.redactor.redact("Pod: 172.16.50.100")
        assert result.modified
        assert "172.16.50.100" not in result.content
        assert "172.REDACTED." in result.content

    def test_cidr_preserved(self):
        result = self.redactor.redact("Network: 10.100.0.0/16")
        assert result.modified
        assert "10.100.0.0" not in result.content
        assert "/16" in result.content

    def test_consistent_mapping(self):
        content = "IP: 10.50.60.70\nAgain: 10.50.60.70"
        result = self.redactor.redact(content)
        lines = result.content.strip().split('\n')
        placeholder_1 = lines[0].split(": ")[1]
        placeholder_2 = lines[1].split(": ")[1]
        assert placeholder_1 == placeholder_2

    def test_public_ip_not_redacted(self):
        content = "Public: 8.8.8.8"
        result = self.redactor.redact(content)
        assert "8.8.8.8" in result.content

    def test_172_outside_range_not_redacted(self):
        content = "IP: 172.32.1.1"
        result = self.redactor.redact(content)
        assert "172.32.1.1" in result.content

    def test_empty_content(self):
        result = self.redactor.redact("")
        assert not result.modified


class TestDomainRedactor:
    def setup_method(self):
        self.redactor = DomainRedactor()

    def test_internal_domain(self):
        result = self.redactor.redact("Server: myhost.internal")
        assert result.modified
        assert "myhost.internal" not in result.content
        assert "redacted-domain-" in result.content

    def test_corp_domain(self):
        result = self.redactor.redact("URL: https://app.mycompany.corp/api")
        assert result.modified
        assert "app.mycompany.corp" not in result.content

    def test_http_proxy(self):
        result = self.redactor.redact("http_proxy=http://proxy.company.com:8080")
        assert result.modified
        assert "proxy.company.com" not in result.content
        assert "REDACTED_PROXY" in result.content

    def test_no_proxy(self):
        result = self.redactor.redact("NO_PROXY=localhost,127.0.0.1,.internal,.corp")
        assert result.modified
        assert "REDACTED_NO_PROXY" in result.content

    def test_public_domain_not_redacted(self):
        result = self.redactor.redact("URL: https://github.com/ansible")
        assert "github.com" in result.content

    def test_empty_content(self):
        result = self.redactor.redact("")
        assert not result.modified


class TestConfigMapRedactor:
    def setup_method(self):
        self.redactor = ConfigMapRedactor()

    def test_ca_configmap_redacted(self):
        content = """apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-root-ca.crt
data:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAKL0UG+mRaqg
    -----END CERTIFICATE-----
"""
        result = self.redactor.redact(content)
        assert result.modified
        assert "MIIDXTCCAkWg" not in result.content
        assert "[REDACTED]" in result.content

    def test_normal_configmap_not_redacted(self):
        content = """apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  key: value
"""
        result = self.redactor.redact(content)
        assert not result.modified

    def test_empty_content(self):
        result = self.redactor.redact("")
        assert not result.modified


class TestRedactorChain:
    def test_combined_redaction(self):
        content = """Server: 10.50.60.70
PASSWORD=secret123
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG
-----END CERTIFICATE-----
Domain: app.internal
"""
        chain = RedactorChain(get_default_redactors())
        result = chain.redact(content)

        assert result.modified
        assert "10.50.60.70" not in result.content
        assert "secret123" not in result.content
        assert "MIIDXTCCAkWg" not in result.content
        assert "app.internal" not in result.content

    def test_empty_content(self):
        chain = RedactorChain(get_default_redactors())
        result = chain.redact("")
        assert not result.modified
