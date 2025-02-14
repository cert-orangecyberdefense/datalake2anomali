from datetime import datetime, timedelta, timezone
import asyncio
import config
import copy
import os
import json
import requests
from datalake import Datalake, Output
from dotenv import load_dotenv
from constants import (
    DTL_TO_ANOMALI_TYPE,
    ANOMALI_PAYLOAD_TEMPLATE,
    ANOMALI_OBJECT_TEMPLATE,
    INDICATOR_TEMPLATE,
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
            "Content-Type": "application/json",
        }

    def init(self) -> bool:
        return True

    def _prepareIndicatorPayload(self, indicators: list) -> dict:
        payload = copy.deepcopy(ANOMALI_PAYLOAD_TEMPLATE)
        expiration_ts = datetime.now(timezone.utc) + timedelta(hours=1)
        payload["meta"].update(
            {
                "classification": config.anomali_classification,
                "expiration_ts": expiration_ts.strftime("%Y-%m-%dT%H:%M:%S"),
            }
        )

        for indicator in indicators:
            anomali_object = copy.deepcopy(ANOMALI_OBJECT_TEMPLATE)
            if indicator["anomali_type"] == "md5":
                # Check if md5 is available for the file
                if indicator["hashes_md5"]:
                    anomali_object[indicator["anomali_type"]] = indicator["hashes_md5"]
                else:
                    continue
            else:
                anomali_object[indicator["anomali_type"]] = indicator["atom_value"]

            anomali_object.update(
                {
                    "confidence": max(indicator["threat_scores"]),
                    "itype": indicator["anomali_itype"],
                    "severity": indicator["anomali_severity"],
                }
            )
            anomali_object["tags"].append(
                {
                    # Dataset name tag
                    "name": indicator["dataset_name"],
                    "tlp": config.tags_tlp,
                }
            )

            if config.add_dtl_tags:
                for tag in indicator["threat_tags"]:
                    anomali_object["tags"].append({"name": tag, "tlp": config.tags_tlp})

            payload["objects"].append(anomali_object)

        return payload

    def uploadPayload(self, payload):
        r = requests.request(
            "PATCH",
            self.intelligence_url,
            data=json.dumps(payload),
            headers=self.headers,
            verify=self.ssl_verify,
            proxies=self.proxies,
        )
        if r.status_code == 202:
            self.logger.debug(
                f"Intelligence uploaded successfully to {self.anomali_url}"
            )
        elif (
            r.status_code == 400
            and "Data exceeds maximum allowed size" in str(r.text)
            and len(payload["objects"]) > 1
        ):
            # We split the objects list in two
            split_index = len(payload["objects"]) // 2
            payload_1 = copy.deepcopy(payload)
            payload_2 = copy.deepcopy(payload)
            payload_1["objects"] = payload["objects"][:split_index]
            payload_2["objects"] = payload["objects"][split_index:]
            self.uploadPayload(payload_1)
            self.uploadPayload(payload_2)
        else:
            self.logger.error(
                f"Error {r.status_code} during upload of intelligence to {self.anomali_url}. "
                f"Response Text: {r.text}, Headers: {r.headers}."
            )
            self.logger.debug(f"Request Payload: {payload}")


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

    def _checkProvidedDatalakeQuery(self, query):
        if (
            query.get("query_hash")
            and query.get("dataset_name")
            and query.get("anomali_severity")
        ):
            return True
        else:
            self.logger.error(
                f"Missing at least one required field for datalake_query among: query_hash: {query.get('query_hash')}, dataset_name: {query.get('dataset_name')}, anomali_severity: {query.get('anomali_severity')} . This query will be skipped."
            )
            return False

    def _getDatalakeThreats(self):
        query_fields = ["atom_type", "atom_value", ".hashes.md5", "threat_scores"]

        if config.add_dtl_tags:
            query_fields.append("tags")

        dtl = Datalake(
            longterm_token=os.environ["OCD_DATALAKE_LONG_TERM_TOKEN"],
            proxies=config.proxies,
            verify=config.ssl_verify,
            env=os.getenv("OCD_DATALAKE_ENV", "prod"),
        )
        coroutines = []
        valid_datalake_queries = []

        for query in config.datalake_queries:
            if self._checkProvidedDatalakeQuery(query):
                valid_datalake_queries.append(query)
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

        return results, valid_datalake_queries

    def _generateIndicators(self, bulk_searches_results, valid_datalake_queries):
        self.logger.info("Generating indicators ...")
        indicators = []

        for index, bulk_search_result in enumerate(bulk_searches_results):
            for threat in bulk_search_result["results"]:
                indicator = copy.deepcopy(INDICATOR_TEMPLATE)
                if DTL_TO_ANOMALI_TYPE.get(threat[0]):
                    anomali_type = DTL_TO_ANOMALI_TYPE.get(threat[0])
                    if anomali_type == "md5" and not threat[2]:
                        self.logger.debug(
                            f"Atom type {threat[0]} without MD5 not supported by Anomali ThreatStream - discarded."
                        )
                        continue

                    # Try to assign iType defined by user, Assign default iType if missing
                    anomali_itype = (
                        valid_datalake_queries[index]
                        .get("anomali_itype", {})
                        .get(anomali_type, config.default_itype.get(anomali_type))
                    )

                    indicator.update(
                        {
                            "dataset_name": valid_datalake_queries[index][
                                "dataset_name"
                            ],
                            "anomali_type": anomali_type,
                            "anomali_itype": anomali_itype,
                            "anomali_severity": valid_datalake_queries[index][
                                "anomali_severity"
                            ],
                            "atom_type": threat[0],
                            "atom_value": threat[1],
                            "hashes_md5": threat[2] if anomali_type == "md5" else None,
                            "threat_scores": threat[3],
                            "threat_tags": threat[4] if len(threat) > 4 else [],
                        }
                    )
                    indicators.append(indicator)
                else:
                    self.logger.debug(
                        f"Atom type {threat[0]} not supported by Anomali ThreatStream - discarded."
                    )

        self.logger.info("Indicators generated")

        return indicators

    def uploadIndicatorsToAnomali(self):
        anomali_api = AnomaliApi(
            ssl_verify=config.ssl_verify, proxies=config.proxies, logger=self.logger
        )
        bulk_searches_results, valid_datalake_queries = self._getDatalakeThreats()
        indicators = self._generateIndicators(
            bulk_searches_results, valid_datalake_queries
        )
        payload = anomali_api._prepareIndicatorPayload(indicators=indicators)
        anomali_api.uploadPayload(payload)

        return
