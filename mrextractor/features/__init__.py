"""
Feature extractor classes.
Contains classes which their main job is to extract specific information from
a raw executable.

Example:
>>> import mrextractor as mre
>>> header_extractor = mre.features.ELFHeader()
>>> binary = open('/bin/ls', 'rb').read()
>>> header_extractor.extract_features(binary)
{'header_size': 64, 'entrypoint': 24880, 'file_type': 'DYNAMIC', ... ,'processor_flag': 0}
"""

from mrextractor.features.base import BaseFeature, ByteCounts, BinaryImage, ExportedFunctions, FileSize, ImportedFunctions, Strings, URLs
from mrextractor.features.elf import BaseELFFeature, ELFHeader, ELFSections, ELFLibraries
from mrextractor.features.pe import PEGeneralFileInfo, PEMSDOSHeader, PEHeader, PEOptionalHeader, PELibraries, PESections

__all__ = [
    'BaseELFFeature',
    'BaseFeature',
    'ByteCounts',
    'BinaryImage',
    'ELFHeader',
    'ELFSections',
    'ELFLibraries',
    'ExportedFunctions',
    'FileSize',
    'ImportedFunctions',
    'PEGeneralFileInfo',
    'PEMSDOSHeader',
    'PEHeader',
    'PEOptionalHeader',
    'PELibraries',
    'PESections',
    'Strings',
    'URLs',
]
