"""Nucleotide: a URL-snippet lookup table builder for Nuclei templates."""

__version__ = "0.1.0"

from .build import build_lookup
from .snippets import compute_unique_snippets

__all__ = ["build_lookup", "compute_unique_snippets", "__version__"]
