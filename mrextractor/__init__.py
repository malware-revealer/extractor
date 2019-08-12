"""
mrextractor is a Python library for extracting features from binaries.
mrextractor is useful for doing static analysis or extracting features for doing
machine learning classification.
"""

from mrextractor import features
from mrextractor.extractor import new
from .version import __version__

__all__ = ['extractor', 'features']
