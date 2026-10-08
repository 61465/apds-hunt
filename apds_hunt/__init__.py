"""
apds-hunt — Reference implementation of Asymmetric Patch Detection for Symmetric APIs.

Public teaching edition v0.1. Full methodology spec at
https://github.com/61465/apds-hunt/blob/main/docs/METHODOLOGY.md
"""

__version__ = "0.1.0"
__author__ = "NEXUS Zone Research"
__email__ = "abdarahman10555@gmail.com"
__license__ = "MIT"

from .xor_rule import XORFinding, evaluate_xor_rule
from .verb_pairs import PUBLIC_VERB_PAIRS, find_sibling_candidates
from .patch_parser import PatchedFunction, parse_patch_commit
from .function_extractor import FunctionDefinition, extract_functions

__all__ = [
    "__version__",
    "XORFinding",
    "evaluate_xor_rule",
    "PUBLIC_VERB_PAIRS",
    "find_sibling_candidates",
    "PatchedFunction",
    "parse_patch_commit",
    "FunctionDefinition",
    "extract_functions",
]
