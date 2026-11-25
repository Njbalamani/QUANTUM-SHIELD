import hashlib
import re

from django.conf import settings

from core.audit import record_audit

from .models import Scan, ScanFinding, ScanPattern, ScanSource, ScanStatus

DEFAULT_PATTERNS = [
    {
        "name": "RSA public-key cryptography",
        "description": "RSA key material or RSA-based configuration was detected.",
        "pattern": r"\bRSA(?:[\s-]?(?:1024|2048|3072|4096|8192))?\b",
        "category": "crypto",
        "severity": "high",
        "recommendation": "Replace RSA with a NIST-approved post-quantum KEM or signature scheme.",
    },
    {
        "name": "ECDSA or elliptic-curve cryptography",
        "description": "Elliptic-curve signing or key agreement parameters were detected.",
        "pattern": r"\b(?:ECDSA|ECDH|ECC|secp256k1|secp384r1|prime256v1|P-256|P-384|P-521)\b",
        "category": "crypto",
        "severity": "high",
        "recommendation": "Migrate elliptic-curve schemes to ML-DSA, SLH-DSA, or ML-KEM.",
    },
    {
        "name": "Diffie-Hellman key exchange",
        "description": "Classical Diffie-Hellman key exchange parameters were detected.",
        "pattern": r"\b(?:Diffie[\s-]?Hellman|DHE?|DH)\b",
        "category": "crypto",
        "severity": "high",
        "recommendation": "Use ML-KEM or a hybrid KEM for key establishment.",
    },
    {
        "name": "DSA signatures",
        "description": "The Digital Signature Algorithm is deprecated for new systems.",
        "pattern": r"\bDSA\b",
        "category": "crypto",
        "severity": "medium",
        "recommendation": "Replace DSA signatures with ML-DSA or SLH-DSA.",
    },
    {
        "name": "MD5 hash function",
        "description": "MD5 is broken and must not be used for integrity or signatures.",
        "pattern": r"\bMD5\b",
        "category": "hash",
        "severity": "critical",
        "recommendation": "Replace MD5 with SHA-256, SHA-3, or a post-quantum-safe signature scheme.",
    },
    {
        "name": "SHA-1 hash function",
        "description": "SHA-1 is deprecated because of practical collision attacks.",
        "pattern": r"\bSHA[\s_-]?1\b",
        "category": "hash",
        "severity": "high",
        "recommendation": "Replace SHA-1 with SHA-256 or SHA-3.",
    },
    {
        "name": "TLS 1.0 or TLS 1.1 protocol",
        "description": "An obsolete TLS protocol version was detected.",
        "pattern": r"\bTLS[\s_-]?v?1(?:\.0|\.1)?\b",
        "category": "protocol",
        "severity": "high",
        "recommendation": "Disable TLS 1.0/1.1 and require TLS 1.2 or TLS 1.3.",
    },
    {
        "name": "DES or 3DES cipher",
        "description": "DES and 3DES use small blocks and obsolete key sizes.",
        "pattern": r"\b(?:3DES|DES)\b",
        "category": "crypto",
        "severity": "high",
        "recommendation": "Replace DES/3DES with AES-GCM or a quantum-safe authenticated cipher suite.",
    },
    {
        "name": "RC4 stream cipher",
        "description": "RC4 has known biases and is prohibited by current standards.",
        "pattern": r"\bRC4\b",
        "category": "crypto",
        "severity": "high",
        "recommendation": "Remove RC4 from all cipher suites and use AES-GCM or ChaCha20-Poly1305.",
    },
    {
        "name": "Blowfish or RC2 cipher",
        "description": "Legacy 64-bit block ciphers were detected.",
        "pattern": r"\b(?:BLOWFISH|BF-CBC|RC2)\b",
        "category": "crypto",
        "severity": "medium",
        "recommendation": "Replace Blowfish/RC2 with AES-GCM or a post-quantum-ready cipher suite.",
    },
    {
        "name": "SSLv3 protocol",
        "description": "SSLv3 is obsolete and vulnerable to downgrade attacks.",
        "pattern": r"\bSSL[\s_-]?v?3(?:\.0)?\b",
        "category": "protocol",
        "severity": "critical",
        "recommendation": "Disable SSLv3 and require TLS 1.2 or TLS 1.3.",
    },
    {
        "name": "Legacy OpenSSL library reference",
        "description": "A legacy OpenSSL or libcrypto library reference was detected.",
        "pattern": r"\b(?:OpenSSL(?:\s+\d+(?:\.\d+)+)?|libcrypto)\b",
        "category": "library",
        "severity": "medium",
        "recommendation": "Upgrade to a current OpenSSL release with quantum-safe provider support.",
    },
]


def _max_bytes():
    try:
        value = int(getattr(settings, "QS_MAX_UPLOAD_MB", 2))
    except (TypeError, ValueError):
        value = 2
    return max(value, 0) * 1024 * 1024


def ensure_default_patterns():
    created = 0
    for item in DEFAULT_PATTERNS:
        _, was_created = ScanPattern.objects.get_or_create(name=item["name"], defaults=item)
        if was_created:
            created += 1
    return created


def finding_line_column(text, start):
    prefix = text[:start]
    line = prefix.count("\n") + 1
    last_newline = prefix.rfind("\n")
    column = start - last_newline
    return line, column


def scan_text(
    text,
    *,
    name="Text scan",
    source=ScanSource.TEXT,
    location="",
    organization=None,
    created_by=None,
    request=None,
):
    if not isinstance(text, str):
        raise ValueError("text must be a string.")
    if not text.strip():
        raise ValueError("text must not be empty.")
    encoded = text.encode("utf-8")
    if len(encoded) > _max_bytes():
        raise ValueError("text exceeds the maximum allowed upload size.")

    by_severity = {}
    by_category = {}
    findings = []
    for pattern in ScanPattern.objects.filter(enabled=True):
        try:
            regex = re.compile(pattern.pattern, re.IGNORECASE)
        except re.error:
            continue
        for match in regex.finditer(text):
            matched_text = match.group(0)[:300]
            line_number, column_number = finding_line_column(text, match.start())
            findings.append(
                ScanFinding(
                    scan=None,
                    pattern=pattern,
                    line_number=line_number,
                    column_number=column_number,
                    matched_text=matched_text,
                    severity=pattern.severity,
                    category=pattern.category,
                    message=pattern.description or f"{pattern.name} detected.",
                    recommendation=pattern.recommendation,
                )
            )
            by_severity[pattern.severity] = by_severity.get(pattern.severity, 0) + 1
            by_category[pattern.category] = by_category.get(pattern.category, 0) + 1

    summary = {
        "total": len(findings),
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
    }
    scan = Scan.objects.create(
        name=name[:200],
        source=source,
        location=location,
        content_hash=hashlib.sha256(encoded).hexdigest(),
        status=ScanStatus.COMPLETED,
        summary=summary,
        organization=organization,
        created_by=created_by,
    )
    for finding in findings:
        finding.scan = scan
    if findings:
        ScanFinding.objects.bulk_create(findings)

    record_audit(
        request,
        "scanner.scan.create",
        obj=scan,
        details=summary,
        user=created_by,
    )
    return (
        Scan.objects.prefetch_related("findings")
        .select_related("organization", "created_by")
        .get(pk=scan.pk)
    )


def scan_upload(uploaded_file, **kwargs):
    chunks = []
    total = 0
    maximum = _max_bytes()
    for chunk in uploaded_file.chunks():
        total += len(chunk)
        if total > maximum:
            raise ValueError("file exceeds the maximum allowed upload size.")
        chunks.append(chunk)
    text = b"".join(chunks).decode("utf-8", errors="replace")
    kwargs["source"] = ScanSource.FILE
    kwargs["location"] = uploaded_file.name
    return scan_text(text, **kwargs)
