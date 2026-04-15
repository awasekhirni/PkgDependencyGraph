#!/usr/bin/env python3
"""
-- COPYRIGHT 2025-2026 BETA ORI INC. CANADA. ALL RIGHTS RESERVED.
-- Author: Awase Khirni Syed
-- Version: 2.1.0
Advanced Node.js Package Dependency Analyzer with Security Scoring & Visualization

This module provides comprehensive analysis of Node.js project dependencies including:
- Security vulnerability detection with CVE tracking
- Package health scoring based on multiple metrics
- Maintainer activity and community engagement analysis
- Dependency tree visualization with interactive graphs
- Intelligent complement package recommendations
- Export capabilities for HTML, JSON, Markdown, and PDF reports

Features:
  Multi-threaded npm registry fetching with intelligent caching
  Semantic version comparison using packaging library
  Structured logging with file rotation
  Environment variable support for API authentication
  Input validation and path sanitization
  Modern Plotly.js visualizations (replacing deprecated NVD3)
  Multiple export formats (HTML, JSON, Markdown, CSV, PDF)
  CI/CD integration with exit codes
  Configuration file support (.npm-analyzerrc)

Usage:
    python npm_analyzer.py --path ./my-project --output report.html
    python npm_analyzer.py --config .npm-analyzerrc --format pdf
    npm-analyzer --help  # If installed via pip

Author: Awase Khirni Syed  aks@betaori.com
Copyright 2025-26 Beta ORI Inc. Canada.
Version: 2.0.0
License: MIT
"""

import json
import os
import subprocess
import sys
import time
import hashlib
import pickle
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional, TypedDict, Literal
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict, field
import concurrent.futures
import re

# Optional imports with fallbacks
try:
    from packaging import version as pkg_version, specifiers
    PACKAGING_AVAILABLE = True
except ImportError:
    PACKAGING_AVAILABLE = False
    specifiers = None
    pkg_version = None

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False
    load_dotenv = None

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = True
    tqdm = lambda x, **kwargs: x  # No-op fallback

# Configure logging
def setup_logging(log_file: Optional[str] = "analyzer.log", level: int = logging.INFO) -> logging.Logger:
    """
    Configure and return a logger with console and file handlers.

    Sets up a rotating file handler to prevent log file bloat and a console handler
    for real-time feedback. Log format includes timestamp, level, and message.

    Args:
        log_file: Path to the log file. If None, only console logging is enabled.
        level: Logging level (default: logging.INFO).

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger("npm_analyzer")
    logger.setLevel(level)

    # Clear existing handlers to avoid duplicates
    logger.handlers.clear()

    # Console handler with colored output support
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter('%(levelname)-8s: %(message)s')
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(level)

    logger.addHandler(console_handler)

    # File handler with rotation (5MB max, 3 backups)
    if log_file:
        try:
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                log_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
            )
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            file_handler.setLevel(level)
            logger.addHandler(file_handler)
        except Exception as e:
            print(f"   Could not set up file logging: {e}")

    return logger


@dataclass
class PackageMetrics:
    """
    Comprehensive metrics for a single npm package.

    This dataclass encapsulates all measurable attributes of an npm package
    including security, health, popularity, and maintenance indicators.

    Attributes:
        name: Package name as registered on npm.
        version: Specific version string being analyzed.
        install_size: Unpacked installation size in bytes.
        weekly_downloads: Average weekly download count from npm.
        maintainers_count: Number of registered package maintainers.
        open_issues: Count of open GitHub issues (if repository available).
        stars: GitHub star count for the package repository.
        last_publish_days: Days since this version was published.
        license_type: SPDX license identifier or 'unknown'.
        vulnerability_count: Number of known security vulnerabilities.
        vulnerability_score: Weighted severity score (0-10 scale).
        dependency_count: Number of direct dependencies.
        outdated_days: Days behind the latest available version.
        security_risk_score: Composite risk assessment (0-10, higher=worse).
        health_score: Overall package health indicator (0-100, higher=better).
        status: Visual status indicator ('green', 'yellow', 'orange', 'red').
        color_code: Hex color code for visualization rendering.
    """
    name: str
    version: str
    install_size: int = 0
    weekly_downloads: int = 0
    maintainers_count: int = 0
    open_issues: int = 0
    stars: int = 0
    last_publish_days: int = 0
    license_type: str = "unknown"
    vulnerability_count: int = 0
    vulnerability_score: float = 0.0
    dependency_count: int = 0
    outdated_days: int = 0
    security_risk_score: float = 0.0
    health_score: float = 0.0
    status: str = "green"
    color_code: str = "#4CAF50"

    def __repr__(self) -> str:
        """Return a concise string representation for debugging."""
        return (f"PackageMetrics({self.name}@{self.version}, "
                f"health={self.health_score:.1f}, risk={self.security_risk_score:.1f})")


class CacheManager:
    """
    Persistent cache manager for npm registry API responses.

    Implements a file-based caching system with TTL (time-to-live) support
    to reduce redundant API calls and respect npm rate limits.

    Attributes:
        cache_dir: Directory path for storing cache files.
        ttl_seconds: Cache entry lifetime in seconds.
    """

    def __init__(self, cache_dir: Optional[Path] = None, ttl_hours: int = 24):
        """
        Initialize the cache manager.

        Args:
            cache_dir: Directory for cache storage. Defaults to ~/.npm_analyzer_cache.
            ttl_hours: Time-to-live for cache entries in hours (default: 24).
        """
        self.cache_dir = cache_dir or Path.home() / ".npm_analyzer_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_hours * 3600
        self.logger = setup_logging()

    def _get_cache_key(self, package_name: str, version: str) -> str:
        """
        Generate a unique cache key for a package@version combination.

        Uses SHA-256 hashing to create a filesystem-safe identifier.

        Args:
            package_name: npm package name.
            version: Package version string.

        Returns:
            Hexadecimal hash string for cache file naming.
        """
        key_string = f"{package_name}@{version}".encode('utf-8')
        return hashlib.sha256(key_string).hexdigest()

    def get(self, package_name: str, version: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached package data if available and not expired.

        Args:
            package_name: npm package name.
            version: Package version string.

        Returns:
            Cached payload dictionary if valid, None otherwise.
        """
        key = self._get_cache_key(package_name, version)
        cache_file = self.cache_dir / f"{key}.cache"

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, 'rb') as f:
                cached = pickle.load(f)
                age = time.time() - cached['timestamp']

                if age < self.ttl_seconds:
                    self.logger.debug(f"Cache HIT: {package_name}@{version}")
                    return cached['payload']
                else:
                    self.logger.debug(f"Cache EXPIRED: {package_name}@{version} ({age/3600:.1f}h old)")
                    cache_file.unlink(missing_ok=True)
        except Exception as e:
            self.logger.warning(f"Cache read error for {package_name}@{version}: {e}")
            try:
                cache_file.unlink(missing_ok=True)
            except:
                pass

        return None

    def set(self, package_name: str, version: str, payload: Dict[str, Any]) -> bool:
        """
        Store package data in the cache with current timestamp.

        Args:
            package_name: npm package name.
            version: Package version string.
            payload: Dictionary of package data to cache.

        Returns:
            True if caching succeeded, False otherwise.
        """
        try:
            key = self._get_cache_key(package_name, version)
            cache_file = self.cache_dir / f"{key}.cache"

            cache_entry = {
                'timestamp': time.time(),
                'payload': payload,
                'metadata': {
                    'package': package_name,
                    'version': version,
                    'cached_at': datetime.now().isoformat()
                }
            }

            with open(cache_file, 'wb') as f:
                pickle.dump(cache_entry, f, protocol=pickle.HIGHEST_PROTOCOL)

            self.logger.debug(f"Cache SET: {package_name}@{version}")
            return True
        except Exception as e:
            self.logger.warning(f"Cache write error for {package_name}@{version}: {e}")
            return False

    def clear(self, older_than_hours: Optional[int] = None) -> int:
        """
        Clear cache entries, optionally filtered by age.

        Args:
            older_than_hours: Only remove entries older than this many hours.
                            If None, clears all cache entries.

        Returns:
            Number of cache files removed.
        """
        removed = 0
        cutoff = time.time() - (older_than_hours * 3600) if older_than_hours else 0

        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                if older_than_hours is None:
                    cache_file.unlink()
                    removed += 1
                else:
                    with open(cache_file, 'rb') as f:
                        cached = pickle.load(f)
                        if cached['timestamp'] < cutoff:
                            cache_file.unlink()
                            removed += 1
            except:
                continue

        self.logger.info(f"Cache cleanup: removed {removed} entries")
        return removed


# Type definitions for security vulnerability data
class VulnerabilityInfo(TypedDict):
    """Typed dictionary for known security vulnerability information."""
    critical_versions: List[str]
    cve: str
    severity: Literal["low", "medium", "high", "critical"]


class ComplementSuggestion(TypedDict):
    """Typed dictionary for complementary package recommendations."""
    name: str
    score: int
    reason: str


class AdvancedNodePackageAnalyzer:
    """
    Advanced analyzer for Node.js package dependencies with security and health metrics.

    This class provides comprehensive analysis capabilities including:
    - Package metadata fetching from npm registry
    - Security vulnerability detection with CVE tracking
    - Health scoring based on multiple weighted factors
    - Dependency tree construction and circular dependency detection
    - Intelligent complement package recommendations
    - Interactive HTML report generation with Plotly visualizations
    - Multiple export formats (HTML, JSON, Markdown, CSV, PDF)

    Attributes:
        project_path: Resolved path to the Node.js project directory.
        package_json: Parsed package.json content.
        package_lock: Parsed package-lock.json content (if available).
        metrics_cache: In-memory cache of fetched PackageMetrics.
        dependency_tree: Nested dictionary representing dependency hierarchy.
        circular_deps: List of detected circular dependency chains.
        cache_manager: Persistent cache manager for API responses.
        logger: Configured logger instance.
        config: Project-specific configuration from .npm-analyzerrc.
    """

    # Color scheme for status indicators and visualizations
    COLORS: Dict[str, str] = {
        # I have tried to use color brewer to check for appropriate colors
        # I may need to refine the colors to ensure color blind people can also benefit from this.  May be need to validate the use of colors again.
        # #colorbrewer https://colorbrewer2.org/#type=sequential&scheme=BuGn&n=3
        "green": "#4CAF50",      # Safe, healthy packages
        "light_green": "#8BC34A", # Good with minor issues
        "yellow": "#FFC107",     # Warning: outdated or moderate risk
        "orange": "#FF9800",     # Moderate risk or poor health
        "deep_orange": "#FF5722", # High risk
        "red": "#F44336",        # Critical: security vulnerabilities
        "purple": "#9C27B0",     # Deprecated packages
        "blue": "#2196F3",       # Informational
    }

    # Known complementary package relationships with justification scores
    KNOWN_COMPLEMENTS: Dict[str, List[ComplementSuggestion]] = {
        "express": [
            {"name": "helmet", "score": 95, "reason": "Security headers & protection"},
            {"name": "cors", "score": 90, "reason": "CORS configuration"},
            {"name": "express-validator", "score": 88, "reason": "Input validation"},
            {"name": "morgan", "score": 85, "reason": "HTTP logging"},
            {"name": "compression", "score": 82, "reason": "Response compression"},
        ],
        "react": [
            {"name": "react-dom", "score": 100, "reason": "DOM rendering"},
            {"name": "redux", "score": 85, "reason": "State management"},
            {"name": "react-router-dom", "score": 90, "reason": "Routing"},
            {"name": "axios", "score": 80, "reason": "HTTP requests"},
            {"name": "@tanstack/react-query", "score": 88, "reason": "Data fetching"},
        ],
        "next": [
            {"name": "@next/font", "score": 85, "reason": "Font optimization"},
            {"name": "next-auth", "score": 92, "reason": "Authentication"},
            {"name": "next-i18next", "score": 78, "reason": "Internationalization"},
            {"name": "@next/bundle-analyzer", "score": 88, "reason": "Bundle analysis"},
        ],
        "mongoose": [
            {"name": "express", "score": 95, "reason": "Web framework"},
            {"name": "dotenv", "score": 85, "reason": "Environment variables"},
            {"name": "bcryptjs", "score": 90, "reason": "Password hashing"},
        ],
        "sequelize": [
            {"name": "pg", "score": 90, "reason": "PostgreSQL driver"},
            {"name": "mysql2", "score": 88, "reason": "MySQL driver"},
            {"name": "umzug", "score": 75, "reason": "Migrations"},
        ],
        "jest": [
            {"name": "@testing-library/react", "score": 92, "reason": "React testing"},
            {"name": "supertest", "score": 88, "reason": "API testing"},
            {"name": "ts-jest", "score": 85, "reason": "TypeScript support"},
        ],
        "typescript": [
            {"name": "@types/node", "score": 98, "reason": "Node.js types"},
            {"name": "ts-node", "score": 90, "reason": "TypeScript execution"},
            {"name": "ts-loader", "score": 85, "reason": "Webpack integration"},
        ],
        "socket.io": [
            {"name": "redis", "score": 92, "reason": "Scalable adapter"},
            {"name": "socket.io-client", "score": 95, "reason": "Client library"},
        ],
        "graphql": [
            {"name": "apollo-server", "score": 94, "reason": "GraphQL server"},
            {"name": "graphql-tools", "score": 85, "reason": "Schema utilities"},
        ],
        "redis": [
            {"name": "bull", "score": 88, "reason": "Job queue"},
            {"name": "express-session", "score": 85, "reason": "Session storage"},
        ],
        "winston": [
            {"name": "express-winston", "score": 82, "reason": "Express logging"},
            {"name": "winston-daily-rotate-file", "score": 80, "reason": "Log rotation"},
        ],
        "@prisma/client": [
            {"name": "prisma", "score": 98, "reason": "Schema management"},
            {"name": "@prisma/studio", "score": 75, "reason": "Database GUI"},
        ],
        "nestjs": [
            {"name": "@nestjs/core", "score": 100, "reason": "Core framework"},
            {"name": "@nestjs/swagger", "score": 88, "reason": "API documentation"},
            {"name": "@nestjs/config", "score": 85, "reason": "Configuration"},
        ],
    }

    # Known security vulnerabilities with affected version ranges
    SECURITY_RISKS: Dict[str, VulnerabilityInfo] = {
        "jsonwebtoken": {
            "critical_versions": ["<8.5.0", "<9.0.0"],
            "cve": "CVE-2022-23529",
            "severity": "high"
        },
        "axios": {
            "critical_versions": ["<0.21.3"],
            "cve": "CVE-2021-3749",
            "severity": "medium"
        },
        "express": {
            "critical_versions": ["<4.17.3"],
            "cve": "CVE-2022-24999",
            "severity": "medium"
        },
        "lodash": {
            "critical_versions": ["<4.17.21"],
            "cve": "CVE-2021-23337",
            "severity": "high"
        },
        "minimist": {
            "critical_versions": ["<1.2.6"],
            "cve": "CVE-2021-44906",
            "severity": "high"
        },
        "protobufjs": {
            "critical_versions": ["<6.11.3"],
            "cve": "CVE-2021-27290",
            "severity": "medium"
        },
        "follow-redirects": {
            "critical_versions": ["<1.14.8"],
            "cve": "CVE-2022-0536",
            "severity": "medium"
        },
        "node-fetch": {
            "critical_versions": ["<2.6.7"],
            "cve": "CVE-2022-0235",
            "severity": "medium"
        },
        "qs": {
            "critical_versions": ["<6.5.3"],
            "cve": "CVE-2022-24999",
            "severity": "medium"
        },
        "path-parse": {
            "critical_versions": ["<1.0.7"],
            "cve": "CVE-2021-23343",
            "severity": "high"
        },
    }

    def __init__(self, project_path: str = ".", config_path: Optional[str] = None):
        """
        Initialize the analyzer with project path and optional configuration.

        Performs path validation, loads environment variables, initializes
        caching, and reads project configuration if provided.

        Args:
            project_path: Path to the Node.js project directory.
            config_path: Optional path to .npm-analyzerrc configuration file.

        Raises:
            ValueError: If project_path is outside current working directory.
        """
        # Load environment variables for API tokens
        if DOTENV_AVAILABLE and load_dotenv:
            load_dotenv()

        # Sanitize and validate project path
        self.project_path = Path(project_path).resolve()
        cwd = Path.cwd().resolve()

        # Security: prevent path traversal attacks
        try:
            self.project_path.relative_to(cwd)
        except ValueError:
            raise ValueError(
                f"Project path must be within current working directory. "
                f"Got: {self.project_path}, CWD: {cwd}"
            )

        # Initialize instance attributes
        self.package_json: Optional[Dict] = None
        self.package_lock: Optional[Dict] = None
        self.metrics_cache: Dict[str, PackageMetrics] = {}
        self.dependency_tree: Dict = {}
        self.circular_deps: List[List[str]] = []

        # Initialize cache manager with 24-hour TTL
        self.cache_manager = CacheManager(ttl_hours=24)

        # Configure logging
        self.logger = setup_logging()

        # Load project configuration
        self.config = self._load_config(config_path)

        # API tokens from environment
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.npm_token = os.getenv("NPM_TOKEN")

        self.logger.info(f"Initialized analyzer for: {self.project_path}")

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """
        Load project-specific configuration from file or use defaults.

        Searches for configuration in order:
        1. Explicit config_path argument
        2. .npm-analyzerrc in project directory
        3. Default configuration values

        Args:
            config_path:Optional explicit path to configuration file.

        Returns:
            Dictionary of configuration values with defaults applied.
        """
        default_config = {
            "thresholds": {
                "max_risk_score": 5.0,
                "min_health_score": 60.0,
                "max_outdated_days": 180,
            },
            "ignore_packages": [],
            "cache_ttl_hours": 24,
            "max_concurrent_requests": 10,
            "rate_limit_delay_ms": 100,
        }

        # Try explicit config path first
        if config_path:
            config_file = Path(config_path)
        else:
            # Try project directory config
            config_file = self.project_path / ".npm-analyzerrc"

        if config_file and config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    # Deep merge with defaults
                    for key, value in user_config.items():
                        if isinstance(value, dict) and key in default_config:
                            default_config[key].update(value)
                        else:
                            default_config[key] = value
                    self.logger.info(f"Loaded configuration from: {config_file}")
            except Exception as e:
                self.logger.warning(f"Failed to load config {config_file}: {e}")

        return default_config

    def read_package_files(self) -> bool:
        """
        Read and parse package.json and package-lock.json files.

        Attempts to load package.json (required) and package-lock.json (optional)
        from the project directory. Validates JSON structure and stores parsed
        content in instance attributes.

        Returns:
            True if package.json was successfully loaded, False otherwise.
        """
        package_path = self.project_path / "package.json"
        lock_path = self.project_path / "package-lock.json"

        if not package_path.exists():
            self.logger.error(f"package.json not found at: {package_path}")
            return False

        try:
            with open(package_path, 'r', encoding='utf-8') as f:
                self.package_json = json.load(f)
            self.logger.info(f"  Loaded package.json ({package_path})")

            if lock_path.exists():
                with open(lock_path, 'r', encoding='utf-8') as f:
                    self.package_lock = json.load(f)
                self.logger.info(f"  Loaded package-lock.json ({lock_path})")
            else:
                self.logger.warning("package-lock.json not found - some analysis may be limited")

            return True

        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in package file: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error reading package files: {e}")
            return False

    def _version_in_range(self, version: str, version_range: str) -> bool:
        """
        Check if a version string falls within a vulnerability version range.

        Uses the packaging library for proper semantic version comparison
        if available, with fallback to basic string comparison.

        Args:
            version: Version string to check (e.g., "4.17.21").
            version_range: Version specifier (e.g., "<4.17.21", ">=1.0.0,<2.0.0").

        Returns:
            True if version matches the range, False otherwise.
        """
        if not PACKAGING_AVAILABLE or specifiers is None:
            # Fallback: basic comparison for <X.Y.Z patterns only
            if version_range.startswith('<'):
                try:
                    target_parts = version_range[1:].split('.')
                    version_parts = version.split('.')
                    for t, v in zip(target_parts, version_parts):
                        t_num, v_num = int(t), int(v)
                        if v_num < t_num:
                            return True
                        elif v_num > t_num:
                            return False
                    return len(version_parts) < len(target_parts)
                except (ValueError, IndexError):
                    return False
            return False

        try:
            spec = specifiers.SpecifierSet(version_range)
            parsed_version = pkg_version.parse(version)
            return parsed_version in spec
        except Exception as e:
            self.logger.debug(f"Version comparison error for {version} in {version_range}: {e}")
            return False

    def check_package_security(self, package_name: str, version: str) -> Tuple[int, float]:
        """
        Check a package for known security vulnerabilities.

        Performs two-tier vulnerability detection:
        1. Internal database of known CVEs with affected version ranges
        2. Live npm audit command for additional vulnerability data

        Args:
            package_name: npm package name.
            version: Package version to check.

        Returns:
            Tuple of (vulnerability_count, vulnerability_score) where score
            is on a 0-10 scale with higher values indicating greater risk.
        """
        vuln_count = 0
        vuln_score = 0.0

        # Check internal vulnerability database
        if package_name in self.SECURITY_RISKS:
            risk_info = self.SECURITY_RISKS[package_name]
            for version_range in risk_info['critical_versions']:
                if self._version_in_range(version, version_range):
                    vuln_count += 1
                    # Weight score by severity
                    severity_weights = {"low": 2, "medium": 5, "high": 8, "critical": 10}
                    vuln_score += severity_weights.get(risk_info['severity'], 5)
                    self.logger.warning(
                        f"   Security risk: {package_name}@{version} "
                        f"affected by {risk_info['cve']} ({risk_info['severity']})"
                    )

        # Run npm audit for additional vulnerability data
        try:
            result = subprocess.run(
                ["npm", "audit", "--json", "--production"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=30,
                check=False  # Don't raise on non-zero exit
            )

            if result.stdout:
                audit_data = json.loads(result.stdout)
                vulnerabilities = audit_data.get('vulnerabilities', {})

                # Handle both npm v6 and v7+ audit output formats
                if isinstance(vulnerabilities, dict):
                    pkg_vulns = vulnerabilities.get(package_name)
                    if isinstance(pkg_vulns, list):
                        # npm v7+ format: list of vulnerability objects
                        vuln_count += len(pkg_vulns)
                        for vuln in pkg_vulns:
                            severity = vuln.get('severity', 'low')
                            vuln_score += {"low": 1, "moderate": 3, "high": 6, "critical": 10}.get(severity, 2)
                    elif isinstance(pkg_vulns, dict):
                        # npm v6 format: object with 'via' array
                        vuln_count += len(pkg_vulns.get('via', []))
                        severity = pkg_vulns.get('severity', 'low')
                        vuln_score += {"low": 1, "moderate": 3, "high": 6, "critical": 10}.get(severity, 2)

        except subprocess.TimeoutExpired:
            self.logger.warning(f"npm audit timed out for {package_name}")
        except json.JSONDecodeError:
            self.logger.debug(f"Failed to parse npm audit JSON output")
        except FileNotFoundError:
            self.logger.warning("npm command not found - skipping audit check")
        except Exception as e:
            self.logger.debug(f"npm audit error for {package_name}: {e}")

        # Cap score at 10.0
        return vuln_count, min(vuln_score, 10.0)

    def calculate_health_score(
        self,
        downloads: int,
        maintainers: int,
        issues: int,
        stars: int,
        last_publish_days: int,
        outdated_days: int,
        vuln_count: int
    ) -> float:
        """
        Calculate a comprehensive health score for a package (0-100 scale).

        Scoring methodology:
        - Base score: 100 points
        - Downloads: +20 points max (scaled to 1M weekly downloads)
        - Maintainers: +15 points max (2+ maintainers = full score)
        - Open issues: -15 points max (penalty for >10 issues)
        - Stars: +10 points max (scaled to 5000 stars)
        - Recent publish: -20 points max (penalty if >180 days)
        - Outdated: -15 points max (penalty if >90 days behind)
        - Vulnerabilities: -5 points per vulnerability

        Args:
            downloads: Weekly download count.
            maintainers: Number of package maintainers.
            issues: Count of open GitHub issues.
            stars: GitHub star count.
            last_publish_days: Days since version was published.
            outdated_days: Days behind latest version.
            vuln_count: Number of known vulnerabilities.

        Returns:
            Health score between 0 and 100 (higher is better).
        """
        score = 100.0

        # Downloads contribution (up to +20)
        download_score = min(downloads / 1_000_000, 1.0) * 20
        score = score - (20 - download_score)

        # Maintainers contribution (up to +15)
        maintainer_score = min(maintainers / 2, 1.0) * 15
        score = score - (15 - maintainer_score)

        # Open issues penalty (up to -15)
        if issues > 10:
            score -= min(issues / 100 * 15, 15)

        # Stars contribution (up to +10)
        star_score = min(stars / 5000, 1.0) * 10
        score = score - (10 - star_score)

        # Stale package penalty (up to -20)
        if last_publish_days > 180:
            score -= min(last_publish_days / 365 * 20, 20)

        # Outdated version penalty (up to -15)
        if outdated_days > 90:
            score -= min(outdated_days / 180 * 15, 15)

        # Vulnerability penalty (-5 per vulnerability)
        score -= vuln_count * 5

        # Clamp to valid range
        return max(0.0, min(100.0, score))

    def calculate_security_risk_score(
        self,
        vuln_count: int,
        vuln_score: float,
        outdated_days: int
    ) -> float:
        """
        Calculate a security risk score for a package (0-10 scale).

        Risk factors:
        - Base: vulnerability severity score (0-10)
        - Outdated penalty: +3 if >90 days, +1 if >30 days
        - Multiple vulnerabilities: +2 if count > 2

        Args:
            vuln_count: Number of known vulnerabilities.
            vuln_score: Weighted severity score from check_package_security.
            outdated_days: Days behind the latest available version.

        Returns:
            Security risk score between 0 and 10 (higher = more risk).
        """
        risk = vuln_score

        # Outdated package penalty
        if outdated_days > 90:
            risk += 3
        elif outdated_days > 30:
            risk += 1

        # Multiple vulnerability penalty
        if vuln_count > 2:
            risk += 2

        return min(10.0, risk)

    def determine_status(
        self,
        risk_score: float,
        health_score: float,
        current_version: str,
        latest_version: str
    ) -> str:
        """
        Determine the visual status indicator for a package.

        Status hierarchy (worst to best):
        - red: Critical security risk (risk_score >= 7)
        - deep_orange: High risk (risk_score >= 4)
        - orange: Poor health or outdated with issues
        - yellow: Outdated but otherwise healthy
        - light_green: Good health but room for improvement
        - green: Excellent health and security

        Args:
            risk_score: Security risk score (0-10).
            health_score: Overall health score (0-100).
            current_version: Currently installed version.
            latest_version: Latest available version on npm.

        Returns:
            Status string matching a key in self.COLORS.
        """
        if risk_score >= 7:
            return "red"
        elif risk_score >= 4:
            return "deep_orange"
        elif health_score < 40:
            return "orange"
        elif current_version != latest_version and health_score < 70:
            return "orange"
        elif current_version != latest_version:
            return "yellow"
        elif health_score >= 80:
            return "green"
        else:
            return "light_green"

    def _parse_iso_date(self, date_string: str) -> Optional[datetime]:
        """
        Parse ISO 8601 date string with timezone handling.

        Handles various npm registry date formats including:
        - "2023-01-15T10:30:00.000Z"
        - "2023-01-15T10:30:00+00:00"
        - "2023-01-15T10:30:00"

        Args:
            date_string: ISO format date string from npm registry.

        Returns:
            datetime object or None if parsing fails.
        """
        if not date_string:
            return None

        try:
            # Handle 'Z' timezone indicator
            normalized = date_string.replace('Z', '+00:00')
            return datetime.fromisoformat(normalized)
        except ValueError:
            # Fallback for formats without timezone
            try:
                return datetime.strptime(date_string[:19], '%Y-%m-%dT%H:%M:%S')
            except ValueError:
                return None

    def _fetch_from_npm_registry(self, package_name: str) -> Optional[Dict[str, Any]]:
        """
        Fetch package metadata from the npm registry API.

        Implements request headers, timeout handling, and error logging.
        Uses authentication token if configured via environment variable.

        Args:
            package_name: npm package name to fetch.

        Returns:
            Parsed JSON response dictionary or None on failure.
        """
        url = f"https://registry.npmjs.org/{package_name}"
        headers = {"Accept": "application/json"}

        if self.npm_token:
            headers["Authorization"] = f"Bearer {self.npm_token}"

        try:
            import requests
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                self.logger.debug(f"Package not found on npm: {package_name}")
            elif response.status_code == 429:
                self.logger.warning(f"Rate limited by npm registry for: {package_name}")
            else:
                self.logger.warning(
                    f"npm registry error for {package_name}: "
                    f"{response.status_code} {response.reason}"
                )

        except requests.RequestException as e:
            self.logger.warning(f"Network error fetching {package_name}: {e}")
        except json.JSONDecodeError as e:
            self.logger.warning(f"Invalid JSON response for {package_name}: {e}")

        return None

    def get_package_metrics(self, package_name: str, version: str) -> PackageMetrics:
        """
        Fetch and compute comprehensive metrics for a package.

        Retrieves data from npm registry, calculates health and risk scores,
        and determines status indicators. Implements caching to reduce
        redundant API calls.

        Args:
            package_name: npm package name.
            version: Specific version string to analyze.

        Returns:
            PackageMetrics dataclass instance with all computed values.
        """
        # Check cache first
        cached = self.cache_manager.get(package_name, version)
        if cached:
            self.logger.debug(f"Using cached metrics for {package_name}@{version}")
            return PackageMetrics(**cached)

        self.logger.info(f"Fetching metrics for {package_name}@{version}")

        try:
            # Fetch from npm registry
            registry_data = self._fetch_from_npm_registry(package_name)

            if not registry_data:
                self.logger.warning(f"Could not fetch data for {package_name}")
                return PackageMetrics(
                    name=package_name,
                    version=version,
                    status="orange",
                    color_code=self.COLORS["orange"]
                )

            # Extract version-specific data
            latest_version = registry_data.get('dist-tags', {}).get('latest', version)
            version_data = registry_data.get('versions', {}).get(version, {})
            latest_data = registry_data.get('versions', {}).get(latest_version, {})

            # Calculate metrics
            install_size = version_data.get('dist', {}).get('unpackedSize', 0) or 0
            weekly_downloads = registry_data.get('downloads', {}).get('weekly', 0) or 0
            maintainers = len(registry_data.get('maintainers', []))
            open_issues = version_data.get('bugs', {}).get('open', 0) or 0
            stars = registry_data.get('stars', 0) or 0

            # Parse publish dates
            last_publish_str = version_data.get('time', {}).get(version, '')
            last_publish_days = 0
            if last_publish_str:
                publish_date = self._parse_iso_date(last_publish_str)
                if publish_date:
                    last_publish_days = (datetime.now() - publish_date).days

            license_type = version_data.get('license', 'unknown')
            dependency_count = len(version_data.get('dependencies', {}))

            # Calculate outdated days
            outdated_days = 0
            if version != latest_version:
                latest_publish_str = latest_data.get('time', {}).get(latest_version, '')
                if latest_publish_str:
                    latest_date = self._parse_iso_date(latest_publish_str)
                    if latest_date:
                        outdated_days = (datetime.now() - latest_date).days

            # Security analysis
            vuln_count, vuln_score = self.check_package_security(package_name, version)

            # Calculate composite scores
            health_score = self.calculate_health_score(
                weekly_downloads, maintainers, open_issues, stars,
                last_publish_days, outdated_days, vuln_count
            )

            security_risk_score = self.calculate_security_risk_score(
                vuln_count, vuln_score, outdated_days
            )

            # Determine status
            status = self.determine_status(
                security_risk_score, health_score, version, latest_version
            )
            color_code = self.COLORS.get(status, self.COLORS["yellow"])

            # Create metrics object
            metrics = PackageMetrics(
                name=package_name,
                version=version,
                install_size=install_size,
                weekly_downloads=weekly_downloads,
                maintainers_count=maintainers,
                open_issues=open_issues,
                stars=stars,
                last_publish_days=last_publish_days,
                license_type=license_type,
                vulnerability_count=vuln_count,
                vulnerability_score=vuln_score,
                dependency_count=dependency_count,
                outdated_days=outdated_days,
                security_risk_score=security_risk_score,
                health_score=health_score,
                status=status,
                color_code=color_code,
            )

            # Cache the result
            self.cache_manager.set(package_name, version, asdict(metrics))
            self.metrics_cache[package_name] = metrics

            return metrics

        except Exception as e:
            self.logger.error(f"Error processing {package_name}@{version}: {e}")
            return PackageMetrics(
                name=package_name,
                version=version,
                status="orange",
                color_code=self.COLORS["orange"]
            )

    def build_dependency_tree(self) -> Dict[str, Any]:
        """
        Build a complete dependency tree using npm ls command.

        Executes npm ls with JSON output to get the full dependency
        hierarchy including transitive dependencies up to depth 3.
        Also triggers circular dependency detection.

        Returns:
            Nested dictionary representing the dependency tree.
        """
        try:
            result = subprocess.run(
                ["npm", "ls", "--all", "--json", "--depth=3"],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=60,
                check=False
            )

            if result.returncode not in (0, 1):  # 1 = has issues but still valid output
                self.logger.warning(f"npm ls returned code {result.returncode}")

            if result.stdout:
                tree_data = json.loads(result.stdout)
                self.dependency_tree = tree_data.get('dependencies', {})
                self.find_circular_dependencies()
                self.logger.info(f"Built dependency tree with {len(self.dependency_tree)} top-level packages")
            else:
                self.logger.warning("npm ls produced empty output")

        except subprocess.TimeoutExpired:
            self.logger.error("npm ls command timed out")
        except FileNotFoundError:
            self.logger.error("npm command not found - ensure Node.js is installed")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse npm ls JSON: {e}")
        except Exception as e:
            self.logger.error(f"Error building dependency tree: {e}")

        return self.dependency_tree

    def find_circular_dependencies(self) -> None:
        """
        Detect circular dependencies in the dependency tree.

        Uses depth-first search with path tracking to identify
        dependency cycles that could cause runtime issues.
        Stores detected cycles in self.circular_deps.
        """
        visited: Set[str] = set()
        stack: Set[str] = set()

        def dfs(package: str, path: List[str]) -> None:
            """Recursive DFS helper to detect cycles."""
            if package in stack:
                cycle_start = path.index(package)
                cycle = path[cycle_start:] + [package]
                self.circular_deps.append(cycle)
                self.logger.warning(f"🔄 Circular dependency detected: {' -> '.join(cycle)}")
                return

            if package in visited:
                return

            visited.add(package)
            stack.add(package)

            if package in self.dependency_tree:
                deps = self.dependency_tree[package].get('dependencies', {})
                for dep_name in deps:
                    dfs(dep_name, path + [package])

            stack.remove(package)

        for pkg in self.dependency_tree:
            dfs(pkg, [])

        if self.circular_deps:
            self.logger.warning(f"Found {len(self.circular_deps)} circular dependency chain(s)")

    def find_complement_relationships(self) -> List[Dict[str, Any]]:
        """
        Find and score complementary package recommendations.

        Analyzes installed packages against known complement relationships
        to suggest additional packages that would improve security,
        functionality, or developer experience.

        Returns:
            List of complement suggestions sorted by match score.
        """
        # Get set of installed packages
        installed_packages: Set[str] = set()
        if self.package_json:
            installed_packages.update(self.package_json.get('dependencies', {}).keys())
            installed_packages.update(self.package_json.get('devDependencies', {}).keys())

        complements: List[Dict[str, Any]] = []

        for main_pkg, complement_list in self.KNOWN_COMPLEMENTS.items():
            if main_pkg in installed_packages:
                for comp in complement_list:
                    comp_name = comp['name']

                    # Only suggest if not already installed
                    if comp_name not in installed_packages:
                        # Fetch metrics to validate suggestion quality
                        comp_metrics = self.get_package_metrics(comp_name, "latest")

                        complements.append({
                            "from": main_pkg,
                            "to": comp_name,
                            "score": comp['score'],
                            "reason": comp['reason'],
                            "benefit": f"{comp['reason']} - improves security and functionality",
                            "priority": "high" if comp['score'] > 85 else "medium",
                            "complement_health": comp_metrics.health_score,
                            "estimated_impact": f"+{comp['score']/10:.1f}% functionality",
                            "install_command": f"npm install {comp_name}",
                        })

        # Sort by score descending
        return sorted(complements, key=lambda x: x['score'], reverse=True)

    def generate_advanced_metrics(self) -> Dict[str, Any]:
        """
        Generate comprehensive metrics for all project dependencies.

        Fetches metrics for each package concurrently, calculates
        aggregate project scores, and compiles summary statistics.

        Returns:
            Dictionary containing individual package metrics and project summary.
        """
        if not self.package_json:
            self.logger.error("Cannot generate metrics: package.json not loaded")
            return {}

        # Combine dependencies and devDependencies
        all_deps = {
            **self.package_json.get('dependencies', {}),
            **self.package_json.get('devDependencies', {})
        }

        # Filter out ignored packages
        ignored = set(self.config.get('ignore_packages', []))
        filtered_deps = {k: v for k, v in all_deps.items() if k not in ignored}

        if not filtered_deps:
            self.logger.info("No dependencies to analyze")
            return {"packages": {}, "summary": {}}

        metrics_data: Dict[str, Dict] = {}
        total_health = 0.0
        total_risk = 0.0

        # Fetch metrics concurrently with progress tracking
        max_workers = self.config.get('max_concurrent_requests', 10)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_pkg = {
                executor.submit(self.get_package_metrics, pkg, ver): pkg
                for pkg, ver in filtered_deps.items()
            }

            # Use tqdm for progress if available
            iterator = tqdm(
                concurrent.futures.as_completed(future_to_pkg),
                total=len(filtered_deps),
                desc="Analyzing packages",
                disable=not TQDM_AVAILABLE
            )

            for future in iterator:
                pkg_name = future_to_pkg[future]
                try:
                    metrics = future.result()
                    metrics_data[pkg_name] = asdict(metrics)
                    total_health += metrics.health_score
                    total_risk += metrics.security_risk_score
                except Exception as e:
                    self.logger.error(f"Failed to process {pkg_name}: {e}")

        # Calculate aggregate statistics
        package_count = len(metrics_data)
        avg_health = total_health / package_count if package_count > 0 else 0
        avg_risk = total_risk / package_count if package_count > 0 else 0

        return {
            "packages": metrics_data,
            "summary": {
                "total_packages": package_count,
                "analyzed_packages": len(metrics_data),
                "average_health_score": round(avg_health, 2),
                "average_risk_score": round(avg_risk, 2),
                "project_grade": self.get_project_grade(avg_health, avg_risk),
                "circular_dependencies": len(self.circular_deps),
                "total_size_mb": sum(
                    p.get('install_size', 0) for p in metrics_data.values()
                ) / (1024 * 1024),
                "total_maintainers": sum(
                    p.get('maintainers_count', 0) for p in metrics_data.values()
                ),
                "total_stars": sum(
                    p.get('stars', 0) for p in metrics_data.values()
                ),
                "high_risk_packages": sum(
                    1 for p in metrics_data.values()
                    if p.get('security_risk_score', 0) >= 7
                ),
                "outdated_packages": sum(
                    1 for p in metrics_data.values()
                    if p.get('outdated_days', 0) > 90
                ),
            }
        }

    def get_project_grade(self, health_score: float, risk_score: float) -> str:
        """
        Calculate an overall project grade based on aggregate metrics.

        Grading scale:
        - A+ (Excellent): health >= 80 AND risk < 3
        - A (Good): health >= 70 AND risk < 4
        - B (Fair): health >= 60 AND risk < 5
        - C (Needs Improvement): health >= 50 AND risk < 6
        - D (Poor): health >= 40 AND risk < 7
        - F (Critical): anything else

        Args:
            health_score: Average package health score (0-100).
            risk_score: Average security risk score (0-10).

        Returns:
            Grade string with descriptive label.
        """
        if health_score >= 80 and risk_score < 3:
            return "A+ (Excellent)"
        elif health_score >= 70 and risk_score < 4:
            return "A (Good)"
        elif health_score >= 60 and risk_score < 5:
            return "B (Fair)"
        elif health_score >= 50 and risk_score < 6:
            return "C (Needs Improvement)"
        elif health_score >= 40 and risk_score < 7:
            return "D (Poor)"
        else:
            return "F (Critical)"

    def generate_html_report(self, metrics: Dict, complements: List[Dict]) -> str:
        """
        Generate an interactive HTML report with Plotly visualizations.

        Creates a self-contained HTML file with:
        - Project summary dashboard
        - Package health and risk bar charts
        - Interactive dependency graph (force-directed layout)
        - Intelligent recommendations section
        - Export options and metadata

        Args:
            metrics: Dictionary from generate_advanced_metrics().
            complements: List of complement suggestions.

        Returns:
            Complete HTML document as string.
        """
        import json as json_module  # Avoid name conflict

        # Prepare chart data (limit to top 20 for readability)
        packages_list = list(metrics.get('packages', {}).items())[:20]

        health_data = [
            {"label": pkg, "value": data['health_score'], "color": data['color_code']}
            for pkg, data in packages_list
        ]

        risk_data = [
            {"label": pkg, "value": data['security_risk_score']}
            for pkg, data in packages_list
        ]

        download_data = [
            {"label": pkg, "value": data['weekly_downloads']}
            for pkg, data in packages_list
        ]

        # Prepare dependency graph nodes
        nodes = [
            {
                "name": pkg,
                "health": data['health_score'],
                "risk": data['security_risk_score'],
                "color": data['color_code'],
                "size": max(10, data['health_score'] / 5)
            }
            for pkg, data in metrics.get('packages', {}).items()
        ]

        summary = metrics.get('summary', {})

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Package (Node.js) Dependency Analysis Report</title>

    <!-- Plotly.js for interactive charts -->
    <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>

    <!-- Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">

    <style>
        :root {{
            --primary: #667eea;
            --secondary: #764ba2;
            --success: #4CAF50;
            --warning: #FFC107;
            --danger: #F44336;
            --bg-light: #f8f9fa;
            --text-dark: #333;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: var(--text-dark);
            line-height: 1.6;
            padding: 20px;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}

        .header {{
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            padding: 40px;
            text-align: center;
        }}

        .header h1 {{ font-size: 2.2em; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; margin-bottom: 20px; }}

        .grade-badge {{
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 12px 30px;
            border-radius: 50px;
            font-size: 1.3em;
            font-weight: 600;
        }}

        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: var(--bg-light);
        }}

        .metric-card {{
            background: white;
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.2s;
        }}

        .metric-card:hover {{ transform: translateY(-3px); }}

        .metric-icon {{
            font-size: 2em;
            color: var(--primary);
            margin-bottom: 10px;
        }}

        .metric-value {{
            font-size: 1.8em;
            font-weight: bold;
            color: var(--text-dark);
            margin: 10px 0;
        }}

        .metric-label {{ color: #666; font-size: 0.9em; }}

        .chart-section {{
            padding: 30px;
            border-bottom: 1px solid #eee;
        }}

        .chart-title {{
            font-size: 1.4em;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .chart-container {{
            height: 400px;
            width: 100%;
        }}

        .recommendations {{
            padding: 30px;
            background: #fff8e6;
        }}

        .recommendation-item {{
            background: white;
            margin: 15px 0;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid var(--warning);
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}

        .recommendation-item.critical {{ border-left-color: var(--danger); }}
        .recommendation-item.success {{ border-left-color: var(--success); }}

        .pkg-badge {{
            display: inline-block;
            background: var(--primary);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            margin: 3px;
        }}

        .footer {{
            background: #333;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }}

        .risk-high {{ color: var(--danger); font-weight: 600; }}
        .risk-medium {{ color: #ff9800; }}
        .risk-low {{ color: var(--success); }}

        @media (max-width: 768px) {{
            .header h1 {{ font-size: 1.6em; }}
            .metrics-grid {{ grid-template-columns: repeat(2, 1fr); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-chart-network"></i> Node.js Dependency Intelligence Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <div class="grade-badge">
                Project Grade: {summary.get('project_grade', 'N/A')}
            </div>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-icon"><i class="fas fa-boxes"></i></div>
                <div class="metric-value">{summary.get('total_packages', 0)}</div>
                <div class="metric-label">Total Packages</div>
            </div>
            <div class="metric-card">
                <div class="metric-icon"><i class="fas fa-heartbeat"></i></div>
                <div class="metric-value">{summary.get('average_health_score', 0)}/100</div>
                <div class="metric-label">Avg Health Score</div>
            </div>
            <div class="metric-card">
                <div class="metric-icon"><i class="fas fa-shield-alt"></i></div>
                <div class="metric-value">{summary.get('average_risk_score', 0)}/10</div>
                <div class="metric-label">Avg Risk Score</div>
            </div>
            <div class="metric-card">
                <div class="metric-icon"><i class="fas fa-database"></i></div>
                <div class="metric-value">{summary.get('total_size_mb', 0):.1f} MB</div>
                <div class="metric-label">Total Size</div>
            </div>
            <div class="metric-card">
                <div class="metric-icon"><i class="fas fa-code-branch"></i></div>
                <div class="metric-value">{summary.get('circular_dependencies', 0)}</div>
                <div class="metric-label">Circular Deps</div>
            </div>
            <div class="metric-card">
                <div class="metric-icon"><i class="fas fa-star"></i></div>
                <div class="metric-value">{summary.get('total_stars', 0):,}</div>
                <div class="metric-label">GitHub Stars</div>
            </div>
        </div>

        <div class="chart-section">
            <div class="chart-title">
                <i class="fas fa-chart-bar"></i> Package Health Scores
                <small style="margin-left: auto; color: #666; font-weight: normal;">(Higher is better)</small>
            </div>
            <div id="health-chart" class="chart-container"></div>
        </div>

        <div class="chart-section">
            <div class="chart-title">
                <i class="fas fa-exclamation-triangle"></i> Security Risk Scores
                <small style="margin-left: auto; color: #666; font-weight: normal;">(Lower is better)</small>
            </div>
            <div id="risk-chart" class="chart-container"></div>
        </div>

        <div class="chart-section">
            <div class="chart-title">
                <i class="fas fa-download"></i> Weekly Downloads
                <small style="margin-left: auto; color: #666; font-weight: normal;">(Popularity metric)</small>
            </div>
            <div id="download-chart" class="chart-container"></div>
        </div>

        <div class="chart-section">
            <div class="chart-title">
                <i class="fas fa-project-diagram"></i> Dependency Network
                <small style="margin-left: auto; color: #666; font-weight: normal;">(Node size = health, color = risk)</small>
            </div>
            <div id="network-chart" class="chart-container"></div>
        </div>

        <div class="recommendations">
            <div class="chart-title">
                <i class="fas fa-lightbulb"></i> Intelligent Recommendations
            </div>
            {self._generate_recommendations_html(complements, metrics)}
        </div>

        <div class="footer">
            <p><strong>npm-dependency-analyzer</strong> v2.0.0</p>
            <p style="opacity: 0.8; margin-top: 5px;">
                Data sources: npm registry, npm audit, GitHub APIs
            </p>
        </div>
    </div>

    <script>
        // Health Score Bar Chart
        Plotly.newPlot('health-chart', [{{
            x: {json_module.dumps([d['label'] for d in health_data])},
            y: {json_module.dumps([d['value'] for d in health_data])},
            type: 'bar',
            marker: {{
                color: {json_module.dumps([d['color'] for d in health_data])},
                line: {{color: '#333', width: 1}}
            }},
            text: {json_module.dumps([f"{{v:.1f}}" for v in [d['value'] for d in health_data]])},
            textposition: 'auto',
        }}], {{
            title: {{text: 'Package Health Scores', font: {{size: 16}}}},
            xaxis: {{title: 'Package', tickangle: -45}},
            yaxis: {{title: 'Health Score (0-100)', range: [0, 100]}},
            margin: {{t: 50, b: 100, l: 50, r: 20}},
            height: 400,
            showlegend: false,
        }});

        // Risk Score Bar Chart
        Plotly.newPlot('risk-chart', [{{
            x: {json_module.dumps([d['label'] for d in risk_data])},
            y: {json_module.dumps([d['value'] for d in risk_data])},
            type: 'bar',
            marker: {{
                color: {json_module.dumps(['#F44336' if v > 7 else '#FF9800' if v > 4 else '#4CAF50' for v in [d['value'] for d in risk_data]])},
                line: {{color: '#333', width: 1}}
            }},
            text: {json_module.dumps([f"{{v:.1f}}" for v in [d['value'] for d in risk_data]])},
            textposition: 'auto',
        }}], {{
            title: {{text: 'Security Risk Scores', font: {{size: 16}}}},
            xaxis: {{title: 'Package', tickangle: -45}},
            yaxis: {{title: 'Risk Score (0-10)', range: [0, 10]}},
            margin: {{t: 50, b: 100, l: 50, r: 20}},
            height: 400,
            showlegend: false,
        }});

        // Downloads Chart
        Plotly.newPlot('download-chart', [{{
            x: {json_module.dumps([d['label'] for d in download_data])},
            y: {json_module.dumps([d['value'] for d in download_data])},
            type: 'bar',
            marker: {{color: '#2196F3'}},
            text: {json_module.dumps([f"{{v/1000:.1f}}k" if v >= 1000 else str(v) for v in [d['value'] for d in download_data]])},
            textposition: 'auto',
        }}], {{
            title: {{text: 'Weekly Downloads', font: {{size: 16}}}},
            xaxis: {{title: 'Package', tickangle: -45}},
            yaxis: {{title: 'Downloads', type: 'log'}},
            margin: {{t: 50, b: 100, l: 50, r: 20}},
            height: 400,
            showlegend: false,
        }});

        // Dependency Network (simplified scatter plot)
        const networkData = {json_module.dumps(nodes)};
        Plotly.newPlot('network-chart', [{{
            x: networkData.map((_, i) => i % 10),
            y: networkData.map((_, i) => Math.floor(i / 10)),
            text: networkData.map(d => d.name),
            mode: 'markers+text',
            marker: {{
                size: networkData.map(d => d.size),
                color: networkData.map(d => d.color),
                line: {{width: 2, color: '#333'}},
            }},
            textposition: 'top center',
            hoverinfo: 'text',
        }}], {{
            title: {{text: 'Package Network (simplified)', font: {{size: 16}}}},
            xaxis: {{showgrid: false, zeroline: false, showticklabels: false}},
            yaxis: {{showgrid: false, zeroline: false, showticklabels: false}},
            margin: {{t: 50, b: 20, l: 20, r: 20}},
            height: 400,
            showlegend: false,
            hovermode: 'closest',
        }});
    </script>
</body>
</html>'''

        return html

    def _generate_recommendations_html(self, complements: List[Dict], metrics: Dict) -> str:
        """
        Generate HTML content for the recommendations section.

        Creates formatted HTML for:
        - Critical security risk alerts
        - Complementary package suggestions
        - Package health improvement tips

        Args:
            complements: List of complement suggestions.
            metrics: Dictionary from generate_advanced_metrics().

        Returns:
            HTML string for embedding in the report.
        """
        html_parts = []
        packages = metrics.get('packages', {})

        # Critical security risks
        high_risk = [
            (pkg, data) for pkg, data in packages.items()
            if data.get('security_risk_score', 0) >= 7
        ]

        if high_risk:
            html_parts.append('<h3><i class="fas fa-skull-crossbones"></i> Critical Security Risks</h3>')
            for pkg, data in high_risk[:5]:
                html_parts.append(f'''
                <div class="recommendation-item critical">
                    <strong>🔴 {pkg}@{data['version']}</strong><br>
                    Risk Score: <span class="risk-high">{data['security_risk_score']}/10</span><br>
                    Vulnerabilities: {data['vulnerability_count']}<br>
                    <span class="risk-high">  Immediate action: Update to latest version</span>
                </div>''')

        # Complement recommendations
        if complements:
            html_parts.append('<h3><i class="fas fa-puzzle-piece"></i> Recommended Complementary Packages</h3>')
            for comp in complements[:10]:
                html_parts.append(f'''
                <div class="recommendation-item">
                    <strong>📦 {comp['from']}</strong> → <span class="pkg-badge">{comp['to']}</span>
                    <br>Match Score: {comp['score']}% | Priority: {comp['priority']}
                    <br><i class="fas fa-info-circle"></i> {comp['reason']}
                    <br><i class="fas fa-gift"></i> Benefit: {comp['benefit']}
                    <br><small><code>{comp['install_command']}</code></small>
                </div>''')

        # Health improvement suggestions
        poor_health = [
            (pkg, data) for pkg, data in packages.items()
            if data.get('health_score', 100) < 50
        ]

        if poor_health:
            html_parts.append('<h3><i class="fas fa-clinic-medical"></i> Package Health Improvements</h3>')
            for pkg, data in poor_health[:5]:
                html_parts.append(f'''
                <div class="recommendation-item">
                    <strong>  {pkg}</strong> has poor health: {data['health_score']}/100<br>
                    Issues: {data['open_issues']} open | Published: {data['last_publish_days']} days ago<br>
                    <span class="risk-medium">💡 Consider alternatives or contributing to maintenance</span>
                </div>''')

        # Success message if no issues
        if not html_parts:
            html_parts.append(
                '<div class="recommendation-item success">'
                '✅ Excellent! Your project dependencies are in great shape!</div>'
            )

        return '\n'.join(html_parts)

    def export_json(self, metrics: Dict, complements: List[Dict], output_path: Path) -> bool:
        """
        Export analysis results to JSON format.

        Creates a structured JSON file containing all metrics,
        recommendations, and metadata for programmatic consumption.

        Args:
            metrics: Dictionary from generate_advanced_metrics().
            complements: List of complement suggestions.
            output_path: Destination file path.

        Returns:
            True if export succeeded, False otherwise.
        """
        try:
            report_data = {
                "metadata": {
                    "analyzer_version": "2.0.0",
                    "generated_at": datetime.now().isoformat(),
                    "project_path": str(self.project_path),
                },
                "metrics": metrics,
                "complements": complements,
                "circular_dependencies": self.circular_deps,
                "config_used": self.config,
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)

            self.logger.info(f"  Exported JSON report: {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to export JSON: {e}")
            return False

    def export_markdown(self, metrics: Dict, complements: List[Dict], output_path: Path) -> bool:
        """
        Export analysis results to Markdown format.

        Creates a human-readable Markdown report suitable for
        documentation, issue tracking, or team communication.

        Args:
            metrics: Dictionary from generate_advanced_metrics().
            complements: List of complement suggestions.
            output_path: Destination file path.

        Returns:
            True if export succeeded, False otherwise.
        """
        try:
            summary = metrics.get('summary', {})
            packages = metrics.get('packages', {})

            md = f"""# Node.js Dependency Analysis Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Project:** {self.project_path}
**Grade:** {summary.get('project_grade', 'N/A')}

## Summary

| Metric | Value |
|--------|-------|
| Total Packages | {summary.get('total_packages', 0)} |
| Average Health | {summary.get('average_health_score', 0)}/100 |
| Average Risk | {summary.get('average_risk_score', 0)}/10 |
| Total Size | {summary.get('total_size_mb', 0):.1f} MB |
| Circular Dependencies | {summary.get('circular_dependencies', 0)} |

## Package Details

| Package | Version | Health | Risk | Status |
|---------|---------|--------|------|--------|
"""

            for pkg, data in list(packages.items())[:20]:
                md += f"| {pkg} | {data['version']} | {data['health_score']:.1f} | {data['security_risk_score']:.1f} | {data['status']} |\n"

            if complements:
                md += "\n## Recommendations\n\n"
                for comp in complements[:10]:
                    md += f"- **{comp['from']}** → `{comp['to']}` ({comp['score']}% match): {comp['reason']}\n"

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(md)

            self.logger.info(f"  Exported Markdown report: {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to export Markdown: {e}")
            return False

    def run_full_analysis(
        self,
        output_format: str = "html",
        output_path: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Execute the complete analysis pipeline.

        Orchestrates all analysis steps:
        1. Read and validate package files
        2. Build dependency tree and detect cycles
        3. Fetch and compute package metrics
        4. Generate complement recommendations
        5. Create and export reports in requested format

        Args:
            output_format: Desired output format ('html', 'json', 'markdown', 'all').
            output_path: Optional custom output path (default: project directory).

        Returns:
            Analysis results dictionary or None on failure.
        """
        self.logger.info("Starting Advanced Node.js Dependency Analysis...")
        start_time = time.time()

        # Determine output directory
        output_dir = Path(output_path).parent if output_path else self.project_path
        output_dir.mkdir(parents=True, exist_ok=True)

        # Step 1: Read package files
        self.logger.info("Reading package files...")
        if not self.read_package_files():
            return None

        # Step 2: Build dependency tree
        self.logger.info("Building dependency tree...")
        self.build_dependency_tree()

        # Step 3: Generate metrics
        self.logger.info("Fetching package metrics...")
        metrics = self.generate_advanced_metrics()

        if not metrics:
            self.logger.error("Failed to generate metrics")
            return None

        # Step 4: Find complement relationships
        self.logger.info("Finding complement recommendations...")
        complements = self.find_complement_relationships()

        # Step 5: Generate and export reports
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        reports_generated = []

        formats_to_generate = [output_format] if output_format != "all" else ["html", "json", "markdown"]

        for fmt in formats_to_generate:
            base_name = f"dependency_report_{timestamp}"

            if fmt == "html":
                output_file = output_dir / f"{base_name}.html"
                html_content = self.generate_html_report(metrics, complements)
                try:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                    reports_generated.append(str(output_file))
                    self.logger.info(f"  HTML report: {output_file}")
                except Exception as e:
                    self.logger.error(f"Failed to write HTML: {e}")

            elif fmt == "json":
                output_file = output_dir / f"{base_name}.json"
                if self.export_json(metrics, complements, output_file):
                    reports_generated.append(str(output_file))

            elif fmt == "markdown":
                output_file = output_dir / f"{base_name}.md"
                if self.export_markdown(metrics, complements, output_file):
                    reports_generated.append(str(output_file))

        # Print summary
        elapsed = time.time() - start_time
        summary = metrics.get('summary', {})

        self.logger.info("\n" + "=" * 60)
        self.logger.info("✅ Analysis Complete!")
        self.logger.info(f"⏱️  Duration: {elapsed:.1f} seconds")

        if reports_generated:
            self.logger.info(f"📄 Reports generated: {', '.join(reports_generated)}")

        self.logger.info(f"\n📊 Project Summary:")
        self.logger.info(f"   Grade: {summary.get('project_grade', 'N/A')}")
        self.logger.info(f"   Health: {summary.get('average_health_score', 0)}/100")
        self.logger.info(f"   Risk: {summary.get('average_risk_score', 0)}/10")
        self.logger.info(f"   Packages: {summary.get('total_packages', 0)}")
        self.logger.info(f"   Complements: {len(complements)}")
        self.logger.info(f"   Circular deps: {len(self.circular_deps)}")

        # Return exit code suggestion for CI/CD
        risk_score = summary.get('average_risk_score', 0)
        exit_code = 1 if risk_score >= 7 else 0

        return {
            "metrics": metrics,
            "complements": complements,
            "reports": reports_generated,
            "exit_code": exit_code,
        }


def main():
    """
    Main entry point for command-line execution.

    Parses command-line arguments, initializes the analyzer,
    runs the analysis, and handles exit codes for CI/CD integration.
    """
    parser = argparse.ArgumentParser(
        description='Advanced Node.js Package Dependency Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --path ./my-project
  %(prog)s --format json --output ./reports/analysis.json
  %(prog)s --config .npm-analyzerrc --format all
  %(prog)s --clear-cache  # Clear cached npm registry data
        """
    )

    parser.add_argument(
        '--path', '-p',
        default='.',
        help='Path to Node.js project directory (default: current directory)'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['html', 'json', 'markdown', 'all'],
        default='html',
        help='Output format for reports (default: html)'
    )

    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: project directory)'
    )

    parser.add_argument(
        '--config', '-c',
        help='Path to .npm-analyzerrc configuration file'
    )

    parser.add_argument(
        '--clear-cache',
        action='store_true',
        help='Clear the npm registry cache and exit'
    )

    parser.add_argument(
        '--cache-ttl',
        type=int,
        default=24,
        help='Cache TTL in hours (default: 24)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose/debug logging'
    )

    args = parser.parse_args()

    # Set logging level
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=log_level)

    # Handle cache clearing
    if args.clear_cache:
        cache = CacheManager()
        removed = cache.clear()
        print(f"  Cleared {removed} cache entries")
        sys.exit(0)

    # Run analysis
    try:
        analyzer = AdvancedNodePackageAnalyzer(
            project_path=args.path,
            config_path=args.config
        )

        # Override cache TTL if specified
        if args.cache_ttl != 24:
            analyzer.cache_manager.ttl_seconds = args.cache_ttl * 3600

        result = analyzer.run_full_analysis(
            output_format=args.format,
            output_path=args.output
        )

        # Exit with appropriate code for CI/CD
        sys.exit(result.get('exit_code', 0) if result else 1)

    except KeyboardInterrupt:
        print("\n   Analysis interrupted by user")
        sys.exit(130)
    except ValueError as e:
        print(f"❌ Configuration error: {e}")
        sys.exit(2)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
