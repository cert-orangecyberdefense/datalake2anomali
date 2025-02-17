INDICATOR_TEMPLATE = {
    "dataset_name": "",
    "anomali_type": "",
    "anomali_itype": "",
    "anomali_severity": "",
    "atom_type": "",
    "atom_value": "",
    "hashes_md5": "",
    "threat_scores": {},
    "threat_tags": [],
}

ANOMALI_PAYLOAD_TEMPLATE = {
    "meta": {
        "allow_update": True,
        "enrich": False,
        "classification": "",
        "expiration_ts": "%Y-%m-%dT%H:%M:%S",
    },
    "objects": [],
}
ANOMALI_OBJECT_TEMPLATE = {"confidence": "", "itype": "", "severity": "", "tags": []}

DTL_TO_ANOMALI_TYPE = {
    "domain": "domain",
    "ip": "srcip",
    "url": "url",
    "email": "email",
    "file": "md5",
}
