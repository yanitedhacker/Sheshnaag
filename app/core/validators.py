"""
Input validation utilities.

Author: Security Enhancement

Provides validation functions for user inputs to prevent injection attacks
and ensure data integrity.
"""

import re
from typing import Optional
from fastapi import HTTPException, status


# CVE ID pattern: CVE-YYYY-NNNNN (4+ digits for the sequence number)
CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

# Patch ID pattern: Vendor-specific or KB numbers
PATCH_ID_PATTERN = re.compile(r'^[A-Za-z0-9_\-\.]+$')

# Safe string pattern (alphanumeric, spaces, basic punctuation)
SAFE_STRING_PATTERN = re.compile(r'^[A-Za-z0-9\s\-_\.,;:\'\"()[\]{}!?@#$%&*+=/<>]+$')

# IP address patterns
IPV4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)
IPV6_PATTERN = re.compile(
    r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
    r'^(?:[0-9a-fA-F]{1,4}:){1,7}:$|'
    r'^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$'
)

# Hostname pattern
HOSTNAME_PATTERN = re.compile(
    r'^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*(?!-)[A-Za-z0-9-]{1,63}(?<!-)$'
)


def validate_cve_id(cve_id: str) -> str:
    """
    Validate and normalize CVE ID format.

    Args:
        cve_id: CVE identifier string

    Returns:
        Normalized (uppercase) CVE ID

    Raises:
        HTTPException: If CVE ID format is invalid
    """
    if not cve_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CVE ID cannot be empty"
        )

    cve_id = cve_id.strip().upper()

    if not CVE_PATTERN.match(cve_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid CVE ID format: '{cve_id}'. Expected format: CVE-YYYY-NNNNN (e.g., CVE-2024-12345)"
        )

    return cve_id


def validate_patch_id(patch_id: str) -> str:
    """
    Validate patch ID format.

    Args:
        patch_id: Patch identifier string

    Returns:
        Validated patch ID

    Raises:
        HTTPException: If patch ID format is invalid
    """
    if not patch_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Patch ID cannot be empty"
        )

    patch_id = patch_id.strip()

    if len(patch_id) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Patch ID too long (max 100 characters)"
        )

    if not PATCH_ID_PATTERN.match(patch_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid patch ID format: '{patch_id}'. Use only alphanumeric characters, hyphens, underscores, and dots."
        )

    return patch_id


def validate_risk_level(risk_level: str) -> str:
    """
    Validate risk level value.

    Args:
        risk_level: Risk level string

    Returns:
        Normalized (uppercase) risk level

    Raises:
        HTTPException: If risk level is invalid
    """
    valid_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    risk_level = risk_level.strip().upper()

    if risk_level not in valid_levels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid risk level: '{risk_level}'. Must be one of: {', '.join(sorted(valid_levels))}"
        )

    return risk_level


def validate_status(status_value: str, valid_statuses: set) -> str:
    """
    Validate status value against allowed statuses.

    Args:
        status_value: Status string
        valid_statuses: Set of valid status values

    Returns:
        Normalized status value

    Raises:
        HTTPException: If status is invalid
    """
    status_value = status_value.strip().lower()

    if status_value not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status: '{status_value}'. Must be one of: {', '.join(sorted(valid_statuses))}"
        )

    return status_value


def validate_vulnerability_status(status_value: str) -> str:
    """Validate vulnerability status."""
    valid_statuses = {"open", "in_progress", "patched", "accepted_risk", "false_positive"}
    return validate_status(status_value, valid_statuses)


def validate_asset_criticality(criticality: str) -> str:
    """Validate asset criticality level."""
    valid_levels = {"critical", "high", "medium", "low"}
    return validate_status(criticality, valid_levels)


def validate_environment(environment: str) -> str:
    """Validate environment value."""
    valid_environments = {"production", "staging", "development", "testing"}
    return validate_status(environment, valid_environments)


def validate_ip_address(ip: str) -> str:
    """
    Validate IP address format (IPv4 or IPv6).

    Args:
        ip: IP address string

    Returns:
        Validated IP address

    Raises:
        HTTPException: If IP address format is invalid
    """
    ip = ip.strip()

    if IPV4_PATTERN.match(ip) or IPV6_PATTERN.match(ip):
        return ip

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Invalid IP address format: '{ip}'"
    )


def validate_hostname(hostname: str) -> str:
    """
    Validate hostname format.

    Args:
        hostname: Hostname string

    Returns:
        Validated hostname

    Raises:
        HTTPException: If hostname format is invalid
    """
    hostname = hostname.strip().lower()

    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Hostname cannot be empty"
        )

    if len(hostname) > 253:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Hostname too long (max 253 characters)"
        )

    if not HOSTNAME_PATTERN.match(hostname):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid hostname format: '{hostname}'"
        )

    return hostname


def sanitize_search_query(query: str, max_length: int = 200) -> str:
    """
    Sanitize search query string.

    Args:
        query: Search query string
        max_length: Maximum allowed length

    Returns:
        Sanitized query string

    Raises:
        HTTPException: If query contains dangerous patterns
    """
    if not query:
        return ""

    query = query.strip()

    if len(query) > max_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Search query too long (max {max_length} characters)"
        )

    # Check for SQL injection patterns
    sql_patterns = [
        r";\s*--",
        r";\s*drop\s+",
        r";\s*delete\s+",
        r";\s*update\s+",
        r";\s*insert\s+",
        r"union\s+select",
        r"or\s+1\s*=\s*1",
        r"'\s*or\s*'",
    ]

    query_lower = query.lower()
    for pattern in sql_patterns:
        if re.search(pattern, query_lower):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid characters in search query"
            )

    return query


def validate_positive_int(value: int, field_name: str, max_value: Optional[int] = None) -> int:
    """
    Validate that a value is a positive integer.

    Args:
        value: Integer value to validate
        field_name: Name of the field (for error messages)
        max_value: Optional maximum allowed value

    Returns:
        Validated integer

    Raises:
        HTTPException: If validation fails
    """
    if value < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a positive integer"
        )

    if max_value is not None and value > max_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} cannot exceed {max_value}"
        )

    return value
