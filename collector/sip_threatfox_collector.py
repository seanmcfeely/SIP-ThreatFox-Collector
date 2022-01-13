#!/usr/bin/env python3

import aiohttp
import asyncio
import argparse
import calendar
import configparser
import datetime
import glob
import json
import logging
import logging.config
import os
import pysip
import sys
import uuid
import time
import traceback
import uuid

import dateutil.parser
from threatfox import ThreatFoxClient
from threatfox.config import get_api_key

HOME_PATH = os.path.dirname(os.path.abspath(__file__))

STORED_DIR_NAME = "incoming_iocs"
STORED_DIR = os.path.join(HOME_PATH, STORED_DIR_NAME)

PROBLEM_INDICATORS = 'problem_indicators'

REQUIRED_DIRS = [STORED_DIR, PROBLEM_INDICATORS, "logs", "var"]


for path in [os.path.join(HOME_PATH, x) for x in REQUIRED_DIRS]:
    if not os.path.isdir(path):
        try:
            os.mkdir(path)
        except Exception as e:
            sys.stderr.write("ERROR: cannot create directory {0}: {1}\n".format(path, str(e)))
            sys.exit(1)


def write_error_report(message):
    """Record unexpected errors."""
    logging.error(message)
    traceback.print_exc()

    try:
        output_dir = "error_reporting"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(
            os.path.join(output_dir, datetime.datetime.now().strftime("%Y-%m-%d:%H:%M:%S.%f")),
            "w",
        ) as fp:
            fp.write(message)
            fp.write("\n\n")
            fp.write(traceback.format_exc())

    except Exception as e:
        traceback.print_exc()


def create_timedelta(timespec):
    """Utility function to translate DD:HH:MM:SS into a timedelta object."""
    duration = timespec.split(":")
    seconds = int(duration[-1])
    minutes = 0
    hours = 0
    days = 0

    if len(duration) > 1:
        minutes = int(duration[-2])
    if len(duration) > 2:
        hours = int(duration[-3])
    if len(duration) > 3:
        days = int(duration[-4])
    return datetime.timedelta(days=days, seconds=seconds, minutes=minutes, hours=hours)


def get_incoming_ioc_paths():
    return glob.glob(f"{os.path.join(STORED_DIR)}/*.json")


def load_ioc(ioc_path: str):
    with open(ioc_path, "r") as fp:
        data = json.load(fp)
    return data

def create_sip_indicator(sip: pysip.pysip.Client, data: dict):
    """Create a SIP indicator."""
    logging.info(f"Attempting to create SIP indicator with following data: {data}")
    if not data['value']:
        logging.error(f"proposed indicator value is empty.")
        return False

    try:
        result = sip.post('/api/indicators', data)
        if 'id' in result:
            logging.info(f"created SIP indicator {result['id']} : {result}")
            return result['id']
    except pysip.ConflictError as e:
        logging.info(f"{e} : SIP indicator already exists with value: {data['value']}")
    #pysip.RequestError for is too long
    except Exception as e:
        # this should never happen
        indicator_file = f"{uuid.uuid4()}.json"
        save_path = os.path.join(HOME_PATH, PROBLEM_INDICATORS, indicator_file)
        with open(save_path, 'w') as fp:
            json.dump(data, fp)
        logging.error(f"unidentified problem creating SIP indicator. saved indicator to {save_path}: {e}")
        write_error_report(f"unidentified problem creating SIP indicator. saved indicator to {save_path}: {e}")

    return False


async def collect(config):

    # time variables
    now = datetime.datetime.utcnow()
    start_time = None
    end_datetime = now
    end_time = end_datetime.strftime("%Y-%m-%d %H:%M:%S")

    # default initial days to collect IOCs is 10
    initial_range = create_timedelta(config["collection_settings"].get("initial_range", "10:00:00:00"))
    # default maximun days to collect IOCs over is 30
    max_time_range = create_timedelta(
        config["collection_settings"].get("maximum_time_range", "30:00:00:00")
    )  # safe guard
    last_search_time_file = os.path.join(HOME_PATH, "var", f"last_search_time")
    if not os.path.exists(os.path.join(last_search_time_file)):
        logging.info(f"{last_search_time_file} doesn't exist. Setting start time to {initial_range}.")
        start_datetime = now - initial_range
        start_time = start_datetime.strftime("%Y-%m-%d %H:%M:%S")
    else:
        try:
            with open(last_search_time_file, "r") as fp:
                start_time = fp.read()
            start_datetime = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            logging.debug(f"last successful search end time: {start_time}")
        except Exception as e:
            logging.error(str(e))
            return False

    if (end_datetime - start_datetime) > max_time_range:
        logging.warning(
            f"it appears this collector hasn't executed in a really long time. Adjusting time frame to {max_time_range}"
        )
        start_datetime = end_datetime - max_time_range
        start_time = start_datetime.strftime("%Y-%m-%d %H:%M:%S")
        logging.info(f"start time adjusted to {start_time}")

    # last collected IOC ID
    last_collected_ioc_id = 0
    last_collected_ioc_id_variable_path = os.path.join(HOME_PATH, "var", f"last_collected_ioc_id")
    if not os.path.exists(os.path.join(last_collected_ioc_id_variable_path)):
        logging.info(f"{last_collected_ioc_id_variable_path} doesn't exist.")
    else:
        try:
            with open(last_collected_ioc_id_variable_path, "r") as fp:
                last_collected_ioc_id = int(fp.read())
            logging.debug(f"last successful ioc collected: {last_collected_ioc_id}")
        except Exception as e:
            logging.error(str(e))
            return False

    # connect to sip
    verify_ssl = config['sip'].get('verify_ssl')
    if not os.path.exists(verify_ssl):
        verify_ssl=config['sip'].getboolean('verify_ssl')
    sip = pysip.Client(f"{config['sip'].get('server')}:{config['sip'].get('port')}", config['sip']['api_key'], verify=verify_ssl)

    def _sip_indicator(type: str, 
                       value: str,
                       reference: dict,
                       tags: list,
                       username=config['sip'].get('user'),
                       case_sensitive=False) -> dict:
        # A sip indicator with some defaults defined.
        return { 'type':type,
                 'status': 'New',
                 'confidence': 'low',
                 'impact' : 'unknown',
                 'value' : value,
                 'references' : [ {'source':"ThreatFox", 'reference': json.dumps(reference)}],
                 'username' :username,
                 'case_sensitive': case_sensitive,
                 'tags': list(set(tags))
                }

    # map ThreatFox IOCs to SIP IOCs
    sip_map = config['sip_mappings']

    # threatfox connection & collection settings
    api_key = config["threatfox"].get("api_key") if config["threatfox"].get("api_key") else None
    api_url = config["threatfox"].get("url") if config["threatfox"].get("url") else None

    threatfox_proxy = config["threatfox"].get("proxy")
    collect_ioc_types = config["collect_ioc_types"]
    ioc_types = [et for et in collect_ioc_types.keys() if collect_ioc_types.getboolean(et)]

    # Check for incoming iocs that still need to be processing.
    ioc_paths = get_incoming_ioc_paths()
    logging.info(f"Found {len(ioc_paths)} incoming iocs...")
    if ioc_paths:
        iocs_from_storage = 0
        # Verify we haven't already processed this IOC before
        # this can be done by IOC ID or IOC type/value

        logging.info(f"successfully posted {iocs_from_storage} to SIP.")

    # TODO: filter IOCs by malware, confidence_level, submitter, etc.
    # get any new iocs
    total_ioc_count = 0
    indicators_created = 0
    indicators_stored = 0
    async with ThreatFoxClient(url=api_url, api_key=api_key) as tfc:
        collection_days = (end_datetime - start_datetime).days
        collection_days = collection_days if collection_days > 0 else 1
        logging.info(f"Collecting ThreatFox iocs from past {collection_days} days")
        results = await tfc.get_iocs(days=collection_days)
        query_status = results.get("query_status")
        if query_status != "ok":
            logging.error(f"got unexpected query status: {query_status}")
            return False
        if results and "data" in results:
            iocs = results["data"]
            total_ioc_count = len(iocs)
            logging.debug(f"got {total_ioc_count} IOC results")
            for ioc in iocs:
                # let an error raise if the data changes
                ioc_id = int(ioc["id"])
                if ioc_id < last_collected_ioc_id:
                    continue
                logging.debug(f"obtained new ioc id: {ioc_id}")
                # TODO: post to SIP
                ioc_type = ioc["ioc_type"]
                ioc_type = 'ip' if ioc_type == 'ip:port' else ioc_type
                itype = sip_map[ioc_type]
                ioc_reference = {_f:_v for _f,_v in ioc.items() if _f  in ['id', 'ioc_type_desc', 'reference']}
                tags = ioc["tags"].append(ioc["malware_printable"])
                idata = _sip_indicator(type=itype, value=ioc['ioc'], reference=ioc_reference, tags=ioc["tags"])
                result = create_sip_indicator(sip, idata)
                if result:
                    logging.info(f"created sip indictor ID={result}")
                    last_collected_ioc_id = ioc_id
                    indicators_created += 1
                else:
                    # SIP post failed, write locally to get picked back up later.
                    with open(os.path.join(STORED_DIR, f"{ioc_id}.json"), "w") as fp:
                        fp.write(json.dumps(ioc))
                        last_collected_ioc_id = ioc_id
                        indicators_stored += 1

    logging.info(
        f"Collected {total_ioc_count} iocs. Created {indicators_created} SIP indicators. Stored {indicators_stored} in {STORED_DIR_NAME}."
    )

    # If here, we consider the collection a success and update our variables.
    try:
        with open(last_search_time_file, "w") as fp:
            fp.write(end_time)
    except Exception as e:
        write_error_report(f"Problem writing last time file: {e}")
        return False
    try:
        with open(last_collected_ioc_id_variable_path, "w") as fp:
            fp.write(str(last_collected_ioc_id))
    except Exception as e:
        write_error_report(f"Problem writing last time file: {e}")
        return False


async def main():

    parser = argparse.ArgumentParser(description="ThreatFox IOC collector.")
    parser.add_argument(
        "--logging-config",
        required=False,
        default="etc/logging.ini",
        dest="logging_config",
        help="Path to logging configuration file.  Defaults to etc/logging.ini",
    )
    parser.add_argument(
        "-c",
        "--config",
        required=False,
        default="etc/config.ini",
        dest="config_path",
        help="Path to configuration file.  Defaults to etc/config.ini",
    )

    args = parser.parse_args()

    # sanity check: work out of home dir
    os.chdir(HOME_PATH)

    # initialize logging
    try:
        logging.config.fileConfig(args.logging_config)
    except Exception as e:
        message = f"ERROR: unable to load logging config from {args.logging_config}: {e}"
        sys.stderr.write(message + "\n")
        write_error_report(message)
        return False

    # less verbose
    logging.getLogger("threatfox.ThreatFoxClient").setLevel(logging.INFO)

    if not os.path.exists(args.config_path):
        logging.error(f"missing config file: {args.config_path}")
        write_error_report(f"missing config file: {args.config_path}")
        return False
    config = configparser.ConfigParser()
    config.optionxform = str  # preserve case
    config.read(args.config_path)

    run_delay_seconds = config["collection_settings"].getint("run_delay_seconds", 300)
    while True:
        await collect(config)
        logging.info(f"waiting {run_delay_seconds} seconds before attempting to collect more iocs ...")
        await asyncio.sleep(run_delay_seconds)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        write_error_report("uncaught exception: {0}".format(str(e)))
