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
process_directory = redact_mod.process_directory


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

    def test_rsa_private_key(self):
        content = ("-----BEGIN RSA PRIVATE KEY-----\n"
                   "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn\n"
                   "-----END RSA PRIVATE KEY-----")
        result = self.redactor.redact(content)
        assert result.modified
        assert "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn" not in result.content
        assert "-----BEGIN RSA PRIVATE KEY-----" in result.content
        assert "-----END RSA PRIVATE KEY-----" in result.content
        assert "[REDACTED]" in result.content

    def test_ec_private_key(self):
        content = ("-----BEGIN EC PRIVATE KEY-----\n"
                   "MHQCAQEEIBkg4LVWM9nuwNSk3yByxZp3\n"
                   "-----END EC PRIVATE KEY-----")
        result = self.redactor.redact(content)
        assert result.modified
        assert "MHQCAQEEIBkg4LVWM9nuwNSk3yByxZp3" not in result.content
        assert "[REDACTED]" in result.content

    def test_generic_private_key(self):
        content = ("-----BEGIN PRIVATE KEY-----\n"
                   "MIIEvgIBADANBgkqhkiG9w0BAQEFAASC\n"
                   "-----END PRIVATE KEY-----")
        result = self.redactor.redact(content)
        assert result.modified
        assert "MIIEvgIBADANBgkqhkiG9w0BAQEFAASC" not in result.content
        assert "[REDACTED]" in result.content

    def test_openssh_private_key(self):
        content = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                   "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ng\n"
                   "-----END OPENSSH PRIVATE KEY-----")
        result = self.redactor.redact(content)
        assert result.modified
        assert "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ng" not in result.content
        assert "[REDACTED]" in result.content


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
        token = "a" * 129
        content = f"something {token} else"
        result = self.redactor.redact(content)
        assert result.modified
        assert token not in result.content
        assert "[REDACTED_TOKEN]" in result.content

    def test_medium_length_string_not_caught(self):
        """Strings between 64 and 127 chars should NOT be caught (reduced false positives)."""
        token = "a" * 80
        content = f"something {token} else"
        result = self.redactor.redact(content)
        assert token in result.content

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

    def test_encryption_key(self):
        content = "DB_ENCRYPTION_KEY=supersecretkey123"
        result = self.redactor.redact(content)
        assert result.modified
        assert "supersecretkey123" not in result.content

    def test_jwt_key(self):
        content = "ANSIBLE_BASE_JWT_KEY=jwt-signing-key-456"
        result = self.redactor.redact(content)
        assert result.modified
        assert "jwt-signing-key-456" not in result.content

    def test_dsn_key(self):
        content = "PG_NOTIFY_DSN=postgres://user:pass@db:5432/awx"
        result = self.redactor.redact(content)
        assert result.modified
        assert "pass" not in result.content

    def test_connection_string_postgres(self):
        content = "postgres://admin:s3cretP4ss@db.example.com:5432/mydb"
        result = self.redactor.redact(content)
        assert result.modified
        assert "s3cretP4ss" not in result.content
        assert "postgres://" in result.content

    def test_connection_string_amqp(self):
        content = "amqp://guest:guest123@rabbit.internal:5672/vhost"
        result = self.redactor.redact(content)
        assert result.modified
        assert "guest123" not in result.content


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

    def test_192_168_redacted(self):
        result = self.redactor.redact("Gateway: 192.168.1.1")
        assert result.modified
        assert "192.168.1.1" not in result.content
        assert "10.REDACTED." in result.content

    def test_192_168_cidr(self):
        result = self.redactor.redact("Subnet: 192.168.0.0/24")
        assert result.modified
        assert "192.168.0.0" not in result.content
        assert "/24" in result.content


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

    def test_svc_cluster_local_preserved(self):
        """Kubernetes .svc.cluster.local DNS names must not be redacted."""
        content = "endpoint: my-service.default.svc.cluster.local"
        result = self.redactor.redact(content)
        assert "my-service.default.svc.cluster.local" in result.content

    def test_svc_cluster_local_with_port(self):
        content = "host: automation-hub.aap.svc.cluster.local:8080"
        result = self.redactor.redact(content)
        assert "automation-hub.aap.svc.cluster.local" in result.content

    def test_non_k8s_local_still_redacted(self):
        """Regular .local domains (not K8s service DNS) should still be redacted."""
        content = "printer: myprinter.office.local"
        result = self.redactor.redact(content)
        assert "myprinter.office.local" not in result.content


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

    def test_preserves_yaml_comments(self):
        """ConfigMap redaction should preserve YAML comments."""
        content = """apiVersion: v1
kind: ConfigMap
metadata:
  name: my-app-ca
  # This is a comment
data:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAKL0UG+mRaqg
    -----END CERTIFICATE-----
"""
        result = self.redactor.redact(content)
        assert result.modified
        assert "# This is a comment" in result.content


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


class TestProcessDirectory:
    """Integration tests for process_directory()."""

    def test_second_file_not_falsely_modified(self, tmp_path):
        """Only files with actual sensitive content should be rewritten."""
        (tmp_path / "a.txt").write_text("IP: 10.1.2.3")
        (tmp_path / "b.txt").write_text("no sensitive data here")
        modified = process_directory(tmp_path, verbose=False)
        assert modified == 1
        assert (tmp_path / "b.txt").read_text() == "no sensitive data here"

    def test_binary_file_skipped(self, tmp_path):
        """Binary files should be skipped entirely, not corrupted."""
        (tmp_path / "text.txt").write_text("PASSWORD=secret")
        (tmp_path / "binary.bin").write_bytes(b'\x00\x01\x02\xff\xfe\xfd')
        modified = process_directory(tmp_path, verbose=False)
        assert modified == 1
        assert (tmp_path / "binary.bin").read_bytes() == b'\x00\x01\x02\xff\xfe\xfd'

    def test_symlinks_not_followed(self, tmp_path):
        """Symlinks should be skipped to avoid modifying files outside the tree."""
        real_file = tmp_path / "real.txt"
        real_file.write_text("PASSWORD=secret")
        link = tmp_path / "link.txt"
        link.symlink_to(real_file)
        modified = process_directory(tmp_path, verbose=False)
        # Only the real file should be modified, not processed twice
        assert modified == 1

    def test_multiple_files_independent_redaction(self, tmp_path):
        """Each file's modification status should be independent."""
        (tmp_path / "has_ip.txt").write_text("Server: 10.0.0.1")
        (tmp_path / "has_cert.txt").write_text(
            "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----"
        )
        (tmp_path / "clean.txt").write_text("nothing sensitive")
        modified = process_directory(tmp_path, verbose=False)
        assert modified == 2
        assert (tmp_path / "clean.txt").read_text() == "nothing sensitive"
