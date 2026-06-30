"""Fetch Nuclei template trees from git or HTTP tarballs."""

from __future__ import annotations

import io
import logging
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

PROJECTDISCOVERY_REPO = "https://github.com/projectdiscovery/nuclei-templates"
MAX_TARBALL_SIZE = 500 * 1024 * 1024  # 500 MB limit


def _validate_repo_url(repo_url: str) -> None:
    """Validate that repo_url is a safe GitHub HTTPS URL.
    
    Raises ValueError if the URL is not safe.
    """
    if not repo_url:
        raise ValueError("Repository URL cannot be empty")
    
    parsed = urlparse(repo_url)
    
    # Only allow HTTPS for security
    if parsed.scheme not in ("https", "http"):
        raise ValueError(f"Unsafe URL scheme: {parsed.scheme}. Only http/https allowed.")
    
    # Only allow github.com or github enterprise domains
    if "github" not in parsed.netloc.lower():
        raise ValueError(f"Repository must be from GitHub, got: {parsed.netloc}")
    
    # Prevent directory traversal
    if ".." in repo_url or parsed.path.count("//") > 1:
        raise ValueError("Repository URL contains suspicious path components")


def _git_available() -> bool:
    """Check if git is available in the system PATH."""
    return shutil.which("git") is not None


def clone_or_update(repo_url: str, dest: Path, depth: int = 1) -> None:
    """Clone or update a git repository with security hardening.
    
    Args:
        repo_url: Repository URL to clone
        dest: Destination path
        depth: Shallow clone depth (default 1)
        
    Raises:
        ValueError: If repo_url or dest path is invalid
        subprocess.CalledProcessError: If git command fails
    """
    _validate_repo_url(repo_url)
    
    if depth < 1:
        raise ValueError(f"Depth must be >= 1, got {depth}")
    
    dest = Path(dest)
    if dest.exists() and dest.is_dir() and (dest / ".git").exists():
        logger.debug(f"Updating existing git repo at {dest}")
        subprocess.run(
            ["git", "-C", str(dest), "fetch", "--depth", str(depth), "origin"],
            check=True,
            timeout=300,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "reset", "--hard", "FETCH_HEAD"],
            check=True,
            timeout=60,
            capture_output=True,
        )
        return
    
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        logger.debug(f"Removing existing directory at {dest}")
        shutil.rmtree(dest)
    
    logger.debug(f"Cloning {repo_url} to {dest} with depth={depth}")
    subprocess.run(
        ["git", "clone", "--depth", str(depth), repo_url, str(dest)],
        check=True,
        timeout=600,
        capture_output=True,
    )


def download_tarball(
    repo_url: str, dest: Path, ref: str = "main", timeout: int = 60
) -> Path:
    """Fall back to a codeload.github.com tarball when git isn't usable.
    
    Args:
        repo_url: Repository URL
        dest: Destination directory
        ref: Git reference (branch/tag)
        timeout: Request timeout in seconds
        
    Returns:
        Path to the extracted templates directory
        
    Raises:
        ValueError: If repo_url or ref is invalid
        urllib.error.URLError: If download fails
        tarfile.TarError: If extraction fails
    """
    _validate_repo_url(repo_url)
    
    if not ref or not ref.isidentifier() and "/" not in ref:
        # Allow refs like "refs/heads/main" but not arbitrary strings
        if not all(c.isalnum() or c in "-_/." for c in ref):
            raise ValueError(f"Invalid git reference: {ref}")
    
    parts = repo_url.rstrip("/").removesuffix(".git").split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid repository URL: {repo_url}")
    
    owner, repo = parts[-2], parts[-1]
    
    # Validate owner and repo names (alphanumeric, dash, underscore)
    for name in [owner, repo]:
        if not all(c.isalnum() or c in "-_" for c in name):
            raise ValueError(f"Invalid repository name: {name}")
    
    url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{ref}"
    logger.debug(f"Downloading tarball from {url}")
    
    dest.mkdir(parents=True, exist_ok=True)
    
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read(MAX_TARBALL_SIZE + 1)
            if len(data) > MAX_TARBALL_SIZE:
                raise ValueError(
                    f"Tarball exceeds size limit ({MAX_TARBALL_SIZE} bytes)"
                )
            logger.debug(f"Downloaded {len(data)} bytes")
    except urllib.error.URLError as e:
        logger.error(f"Failed to download tarball: {e}")
        raise
    
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            # Prevent directory traversal attacks during extraction
            for member in tf.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    raise tarfile.TarError(
                        f"Unsafe tar member path: {member.name}"
                    )
            tf.extractall(dest)
        logger.debug("Tarball extracted successfully")
    except tarfile.TarError as e:
        logger.error(f"Failed to extract tarball: {e}")
        raise
    
    extracted = next((p for p in dest.iterdir() if p.is_dir()), None)
    return extracted or dest


def fetch(
    repo_url: str = PROJECTDISCOVERY_REPO,
    dest: Optional[Path] = None,
    *,
    update: bool = True,
    fallback_ref: str = "main",
) -> Path:
    """Materialize a templates directory and return its path.

    Tries `git clone --depth 1` first, then falls back to a GitHub tarball.
    If `update` is False and the destination already exists, it is reused as-is.
    
    Args:
        repo_url: Repository URL (default: projectdiscovery nuclei-templates)
        dest: Destination directory (default: ~/.cache/nucleotide/templates)
        update: Whether to fetch updates if dest exists
        fallback_ref: Git reference for tarball fallback
        
    Returns:
        Path to the templates directory
        
    Raises:
        ValueError: If URLs or paths are invalid
        subprocess.CalledProcessError: If git operations fail
        urllib.error.URLError: If tarball download fails
    """
    _validate_repo_url(repo_url)
    
    dest = Path(dest) if dest else Path.home() / ".cache" / "nucleotide" / "templates"
    logger.debug(f"Fetch destination: {dest}, update={update}")

    if dest.exists() and any(dest.iterdir()) and not update:
        logger.debug(f"Reusing existing templates at {dest}")
        return dest

    if _git_available():
        try:
            logger.debug("Attempting git clone/update")
            clone_or_update(repo_url, dest)
            return dest
        except subprocess.CalledProcessError as e:
            logger.warning(f"Git operation failed, falling back to tarball: {e}")

    logger.debug("Using tarball download")
    return download_tarball(repo_url, dest, ref=fallback_ref)
