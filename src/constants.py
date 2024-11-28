DATASET_NAME = 0
ANOMALI_TYPE = 1
ANOMALI_ITYPE = 2
ANOMALI_SEVERITY = 3
ATOM_TYPE = 4
ATOM_VALUE = 5
HASHES_MD5 = 6
THREAT_SCORES = 7
THREAT_TAGS = 8

DTL_TO_ANOMALI_TYPE = {
    "fqdn": "domain",
    "domain": "domain",
    "ip": "srcip",
    "url": "url",
    "email": "email",
    "file": "md5"
}
