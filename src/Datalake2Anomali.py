from datetime import datetime, timedelta, timezone
import asyncio
from http.client import HTTPException
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
from models import AnomaliTipReportModel, PatchTipReportModel
from dateutil import parser

load_dotenv()

SUCCESSFUL_HTTP_CODES = [200, 201, 202]
WORLD_WATCH_TIME_FORMAT: str = "%Y-%m-%dT%H:%M:%SZ"
ANOMALI_TIME_FORMAT: str = "%Y-%m-%dT%H:%M:%S.%f%z"

class AnomaliApi:

    GENERIC_WORLD_WATCH_BULLETIN_TAG = "world_watch_advisory"
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
            "content-type": "application/json",
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


    def check_if_bulletin_exists_in_anomali(self, id: int):
        url_params = f"tags={self.GENERIC_WORLD_WATCH_BULLETIN_TAG}&tags=world_watch_{id}&model_type=tipreport"
        get_report_by_id = f"{self.anomali_url}/api/v1/threat_model_search/?{url_params}"

        r = requests.get(get_report_by_id, headers=self.headers)

        if r.status_code not in SUCCESSFUL_HTTP_CODES:
            raise HTTPException(f"Cannot get report from anomali, {r.content}, {r.status_code}")

        tipreport_list = r.json()['objects']

        if not (len(tipreport_list) > 0):
            self.logger.debug(f"Did not find previous report with worldwatch id {id}")
            return None, None


        last_modified = tipreport_list[0]['modified_ts']
        dt_last_modified = parser.parse(last_modified)

        return tipreport_list[0]['id'], dt_last_modified


    def get_datetime_of_last_world_watch_report(self):
        query_params = f"?model_type=tipreport&tags={self.GENERIC_WORLD_WATCH_BULLETIN_TAG}&limit=1"
        url = f"{self.anomali_url}/api/v1/threat_model_search/{query_params}"
        response = requests.get(url, headers=self.headers)

        if response.status_code not in SUCCESSFUL_HTTP_CODES:
            raise HTTPException(f"Cannot get tipreports from ANOMALI, {response.content}, {response.status_code}")

        if len(response.json()['objects']) == 0:
            return None

        return parser.parse(response.json()['objects'][0]['modified_ts'])

    def get_world_watch_tag(self, id):
        return f"world_watch_{id}"

    def map_ww_content_block_to_anomali(self, tipreport_id, content_block_list: list, last_modified = None):
        mapped_blocks = [
            PatchTipReportModel(
                body=block['executive_summary'],
                modified_ts=datetime.strftime(parser.parse(block['timestamp_updated']), ANOMALI_TIME_FORMAT),
                name=block["title"],
                tags=[
                    self.GENERIC_WORLD_WATCH_BULLETIN_TAG,
                    self.get_world_watch_tag(tipreport_id),
                    *block['tags']
                ]
            ).model_dump()
            for block in content_block_list
        ]

        compared_dt = datetime.now() - timedelta(hours=config.upload_frequency)
        if last_modified:
            compared_dt = last_modified

        mapped_blocks = list(
            filter(
                lambda x: parser.parse(x['modified_ts']).replace(tzinfo=timezone.utc) > compared_dt.replace(tzinfo=timezone.utc),
                mapped_blocks
            )
        )

        return mapped_blocks


    def patch_existing_tipreport(self, advisory, tipreport_id, last_modified):
        patch_url = f"{self.anomali_url}/api/v1/tipreport/{tipreport_id}/"

        self.logger.debug(f"Applying patch content blocks to existing tipreport {tipreport_id}, last modified at {last_modified.strftime('%B %d, %Y %I:%M %p')}")

        mapped_blocks = self.map_ww_content_block_to_anomali(tipreport_id, advisory['content_blocks'], last_modified)

        patch_payload = {
            "objects": mapped_blocks
        }

        response = requests.patch(url=patch_url,
                    json=patch_payload,
                    headers=self.headers)

        if response.status_code not in SUCCESSFUL_HTTP_CODES:
            raise HTTPException(f"Cannot patch report, {response.content}, {response.status_code}")


        self.logger.debug(f"Patch response: {response.status_code}, {response.content}")




    def add_new_tipreport(self, advisory):
        add_tipreport_url = f"{self.anomali_url}/api/v1/tipreport/"

        advisory_id = advisory['id']
        content_blocks = advisory['content_blocks']
        earliest_content_block = advisory['content_blocks'][-1]

        report_model: AnomaliTipReportModel = AnomaliTipReportModel(
            body=earliest_content_block['executive_summary'],
            created_ts=advisory['timestamp_created'],
            modified_ts=advisory['timestamp_updated'],
            name=advisory['title'],
            tags=[
                self.get_world_watch_tag(advisory_id),
                self.GENERIC_WORLD_WATCH_BULLETIN_TAG
            ]
        )

        response = requests.post(add_tipreport_url, json=report_model.model_dump(), headers=self.headers)

        self.logger.debug("Added new bulletin")

        tipreport_id: int = response.json()['id']
        patch_url = f"{self.anomali_url}/api/v1/tipreport/{tipreport_id}/"
        mapped_blocks = self.map_ww_content_block_to_anomali(
                            tipreport_id,
                            content_blocks[:-1]
                        )

        if len(mapped_blocks) > 1:
            patch_payload = {"objects": mapped_blocks}

            r = requests.patch(
                url=patch_url,
                json=patch_payload,
                headers=self.headers
            )

            if r.status_code not in SUCCESSFUL_HTTP_CODES:
                raise HTTPException(f"Cannot patch bulletin in anomali, {r.content}, {r.status_code}")

            self.logger.debug(f"Updated newly created tipreport {tipreport_id} history")


    def upload_bulletins(self, advisories):
        for advisory in advisories:
            advisory_id = advisory['id']
            tipreport_id, last_modified = self.check_if_bulletin_exists_in_anomali(advisory_id)
            if tipreport_id:
                self.patch_existing_tipreport(advisory, tipreport_id, last_modified)
            else:
                self.add_new_tipreport(advisory)



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
        self.world_watch_url = os.environ["WORLD_WATCH_URL"]
        self.world_watch_token = os.environ["WORLD_WATCH_TOKEN"]
        self.anomali_api = AnomaliApi(
            ssl_verify=config.ssl_verify, proxies=config.proxies, logger=self.logger
        )


    @property
    def world_watch_headers(self) -> dict:
        return {
            "accept": "application/json",
            "authorization": os.environ.get('WORLD_WATCH_TOKEN')
            }


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

        self.logger.debug(f"Results from datalake {results}")

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
        bulk_searches_results, valid_datalake_queries = self._getDatalakeThreats()
        indicators = self._generateIndicators(
            bulk_searches_results, valid_datalake_queries
        )
        payload = self.anomali_api._prepareIndicatorPayload(indicators=indicators)
        self.anomali_api.uploadPayload(payload)

        return

    def _get_bulletins_from_world_watch(self):
        updated_after_string = (datetime.now() - timedelta(hours=config.upload_frequency)).strftime(WORLD_WATCH_TIME_FORMAT)

        if not config.run_as_cron:
            last_time = self.anomali_api.get_datetime_of_last_world_watch_report()

            if last_time:
                updated_after_string = last_time.strftime(WORLD_WATCH_TIME_FORMAT)

        advisory_endpoint = f"{self.world_watch_url}/api/advisory/?updated_after={updated_after_string}"


        r = requests.get(advisory_endpoint, headers=self.world_watch_headers)

        if r.status_code not in SUCCESSFUL_HTTP_CODES:
            raise HTTPException(f"Cannot get bulletins from world watch, {r.content}, {r.status_code}")

        specific_advisory_endpoint = f"{self.world_watch_url}/api/advisory"
        complete_advisories = []

        for item in r.json()['items']:
            r = requests.get(f"{specific_advisory_endpoint}/{item['id']}", headers=self.world_watch_headers)

            if r.status_code not in SUCCESSFUL_HTTP_CODES:
                raise HTTPException(f"Cannot get complete advisory, {r.content}, {r.status_code}")

            complete_advisory = r.json()
            complete_advisories.append(complete_advisory)

        return complete_advisories


    def upload_bulletins(self):
        try:
            last_advisories = self._get_bulletins_from_world_watch()
            self.anomali_api.upload_bulletins(last_advisories)
        except HTTPException as e:
            self.logger.error(f"Unexpected http error: {repr(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected runtime error: {repr(e)}")