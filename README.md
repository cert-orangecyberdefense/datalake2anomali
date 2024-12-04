# Datalake to Anomali ThreatStream connector

## About the Connector

This connector allows you to ingest **threat indicators (IOCs)** from **Orange Cyberdefense Datalake Platform** to **Anomali ThreatStream**.

## Getting Started

### Prerequisites
Rename the file `src/.env.default` to `src/.env` and replace the environment variables with yours. This file is use to define all the credentials for **Datalake** and **Anomali ThreatStream** APIs.
* Modify the `OCD_DATALAKE_LONG_TERM_TOKEN` and copy here a **Datalake** LongTermToken generated from [My account](https://datalake.cert.orangecyberdefense.com/gui/my-account) page.
  * **IMPORTANT**: the user account used to generate the LongTermToken needs to have `bulk_search` permission.
* Then provide your **Anomali ThreatStream** URL and credentials using the following variables: `ANOMALI_URL`, `ANOMALI_USER` and `ANOMALI_API_KEY`
  * **IMPORTANT**: you must have `Approve Intel` user permission in Anomali ThreatStream to import data via this connector. 

### Configuration

Rename the file `src/config.py.default` to `src/config.py` and adapt the values according to your usage. This file is used to configure the **Datalake API requests** which will be executed and how the data will be ingested into **Anomali ThreatStream**.

You will find comments in the `config.py` for each settings so we will only describe hereunder important things to keep in mind.
#### Run mode
You can choose to schedule the launch of this script on your own or use the connector built-in scheduling capabilities using `run_as_cron` setting.
* If set to true you can choose the frequency of the run using `upload_frequency` setting (use hour as time period).
#### Indicator expiration
In order to keep only fresh indicators active in **Anomali ThreatStream** the connector will set the **Expiration timestamp** of each indicator to `anomali_expiration_period` hours after the import.
* **IMPORTANT**: ensure that `anomali_expiration_period` is always higher than `upload_frequency` when you use the built-in scheduler capabilities or higher than the period you want to run the connector.
#### Datalake queries
The `datalake_queries` defines the list of queries to export indicators from the Datalake.
- **[required]** `query_hash` is the query hash of the Datalake search for which you want to import the data into Anomali. It could be found at the end of the URL when you create your search in the Datalake web interface `https://datalake.cert.orangecyberdefense.com/gui/search?query_hash=<query_hash>`
- **[required]** `dataset_name` will be added as a **tag** to each indicator uploaded and belonging to this search. It's then an easy way to find corresponding indicators in Anomali ThreatStream.
- **[required]** `anomali_severity` defines the **Anomali severity** for uploaded indicators.
- **[optional]** `anomali_itype` if defined allows you to force the **Anomali iType** that will be used for each indicator type. If not defined or missing for some indicator type the default iType specified by `default_itype` will be used. 

## Usage
You can use **Docker** or launch the connector as a standalone Python **script**.

### Docker
To launch the connector execute the CLI command `docker compose up --build -d`, you can then see the logs with the CLI command `docker compose logs -f datalake2anomali`.
Or you can use the make commands `start_docker`|`stop_docker`

### Python script
To launch the connector out of docker you can follow this steps:
1) create a dedicated Python virtual environment with the following command `python3 -m venv .venv`
2) activate the venv `source .venv/bin/activate`
3) install requirements from `src\requirements.txt` with `pip install -r src/requirements.txt`
4) launch the connector `python src/core.py`
5) (You can exit the virtual environment with the `deactivate` command)
Or you can use the make command `start_standalone`

