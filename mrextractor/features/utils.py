import lief


def lief_from_raw(bytes):
    """Create a lief binary object from raw bytes"""

    b_list = list(bytes)
    lief_binary = lief.parse(raw=b_list)
    return lief_binary
