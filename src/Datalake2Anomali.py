from datetime import datetime, timedelta, timezone
import asyncio
import config
import os
import json
import requests
from datalake import Datalake, Output
from dotenv import load_dotenv
from constants import (
    DATASET_NAME,
    ANOMALI_TYPE,
    ANOMALI_ITYPE,
    ANOMALI_SEVERITY,
    ATOM_VALUE,
    HASHES_MD5,
    THREAT_SCORES,
    THREAT_TAGS,
    DTL_TO_ANOMALI_TYPE
)

load_dotenv()


class AnomaliApi:

    def __init__(
            self,
            ssl_verify: bool,
            proxies: dict,
            logger,
    ) -> None:
        self.anomali_url = os.environ["ANOMALI_URL"]
        self.anomali_user = os.environ["ANOMALI_USER"]
        self.anomali_api_key = os.environ["ANOMALI_API_KEY"]
        self.ssl_verify = ssl_verify
        if proxies:
            self.proxies = proxies
        else:
            self.proxies = None
        self.logger = logger

    @property
    def intelligence_url(self) -> str:
        return f"{self.anomali_url}/api/v2/intelligence/"

    @property
    def headers(self) -> dict:
        return {
            "Authorization": f"apikey {self.anomali_user}:{self.anomali_api_key}",
            "Content-Type": "application/json"
        }

    def init(self) -> bool:
        return True

    def _prepareIndicatorPayload(self, indicators: list) -> dict:
        expiration_ts = datetime.now(timezone.utc) + timedelta(hours=1)
        payload = {
            "meta": {
                "allow_update": True,
                "enrich": False,
                "classification": config.anomali_classification,
                "expiration_ts": expiration_ts.strftime('%Y-%m-%dT%H:%M:%S')
            },
            "objects": []
        }

        for indicator in indicators:
            anomali_object = {}
            if indicator[ANOMALI_TYPE] == "md5":
                # Check if md5 is available for the file
                if indicator[HASHES_MD5]:
                    anomali_object[indicator[ANOMALI_TYPE]] = indicator[HASHES_MD5]
                else:
                    continue
            else:
                anomali_object[indicator[ANOMALI_TYPE]] = indicator[ATOM_VALUE]

            anomali_object["confidence"] = max(indicator[THREAT_SCORES])
            anomali_object["itype"] = indicator[ANOMALI_ITYPE]
            anomali_object["severity"] = indicator[ANOMALI_SEVERITY]
            anomali_object["tags"] = [
                {
                    # Dataset name tag
                    "name": indicator[DATASET_NAME],
                    "tlp": config.tags_tlp
                }
            ]

            if config.add_dtl_tags:
                for tag in indicator[THREAT_TAGS]:
                    anomali_object["tags"].append({
                        "name": tag,
                        "tlp": config.tags_tlp
                    })

            payload["objects"].append(anomali_object)

        return payload

    def uploadIndicators(self, indicators: list):
        payload = self._prepareIndicatorPayload(indicators=indicators)

        r = requests.request(
            "PATCH",
            self.intelligence_url,
            data=json.dumps(payload),
            headers=self.headers,
            verify=self.ssl_verify,
            proxies=self.proxies
        )
        if r.status_code == 202:
            self.logger.debug(f"Intelligence uploaded successfully to {self.anomali_url}")
        else:
            self.logger.error(
                f"Error {r.status_code} during upload of intelligence to {self.anomali_url}"
            )


class Datalake2Anomali:
    """
    A class that handles all the logic of the connector: getting the iocs from
    Datalake and send them to Anomali.
    """

    def __init__(
            self,
            logger,
    ):
        self.logger = logger

    def _getDatalakeThreats(self):
        query_fields = ["atom_type", "atom_value", ".hashes.md5", "threat_scores"]

        if config.add_dtl_tags:
            query_fields.append("tags")

        dtl = Datalake(
            longterm_token=os.environ["OCD_DATALAKE_LONG_TERM_TOKEN"],
            proxies=config.proxies,
            verify=config.ssl_verify
        )
        coroutines = []

        for query in config.datalake_queries:
            self.logger.info(
                f"Creating BulkSearch for {query['query_hash']} query_hash ..."
            )

            task = dtl.BulkSearch.create_task(
                query_hash=query["query_hash"], query_fields=query_fields
            )
            coroutines.append(task.download_async(output=Output.JSON))

        loop = asyncio.get_event_loop()
        future = asyncio.gather(*coroutines)
        results = loop.run_until_complete(future)
        for result in results:
            self.logger.info(
                "Get {} threats from Datalake with {} query_hash".format(
                    result["count"], result["advanced_query_hash"]
                )
            )

        return results

    def _generateIndicators(self, bulk_searches_results):
        self.logger.info("Generating indicators ...")
        indicators = []

        for index, bulk_search_result in enumerate(bulk_searches_results):
            dataset_name = config.datalake_queries[index]["dataset_name"]
            anomali_severity = config.datalake_queries[index]["anomali_severity"]

            for threat in bulk_search_result["results"]:
                if DTL_TO_ANOMALI_TYPE.get(threat[0]):
                    anomali_type = DTL_TO_ANOMALI_TYPE.get(threat[0])
                    if anomali_type == "md5" and not threat[2]:
                        self.logger.debug(
                            f"Atom type {threat[0]} without MD5 not supported by Anomali ThreatStream - discarded.")
                        continue

                    anomali_itype = ""
                    if isinstance(config.datalake_queries[index].get("anomali_itype"), dict):
                        # Try to assign iType defined by user
                        anomali_itype = config.datalake_queries[index]["anomali_itype"].get(
                            anomali_type)

                    if not anomali_itype:
                        # Assign default iType if missing
                        anomali_itype = config.default_itype.get(anomali_type)

                    threat.insert(0, anomali_severity)
                    threat.insert(0, anomali_itype)
                    threat.insert(0, anomali_type)
                    threat.insert(0, dataset_name)
                    indicators.append(threat)
                else:
                    self.logger.debug(
                        f"Atom type {threat[0]} not supported by Anomali ThreatStream - discarded.")

        self.logger.info("Indicators generated")

        return indicators

    def uploadIndicatorsToAnomali(self):
        anomali_api = AnomaliApi(ssl_verify=config.ssl_verify, proxies=config.proxies, logger=self.logger)
        bulk_searches_results = self._getDatalakeThreats()
        indicators = self._generateIndicators(bulk_searches_results)

        anomali_api.uploadIndicators(indicators)

        return
