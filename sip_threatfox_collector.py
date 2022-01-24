#!/usr/bin/env python3

import asyncio
import argparse
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
import traceback
import uuid

from typing import List
from urllib.parse import urlparse

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
    """Create a SIP indicator.
    
    Args:
      sip: A pysip client.
      data: Dictionary representation of a sip indicator you want to create.
    Returns:
      The unique ID of the SIP indicator that was created or False.
    """
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
        raise e
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

def format_indicator_for_sip(type: str, 
                       value: str,
                       reference: dict,
                       tags: list,
                       username: str,
                       case_sensitive=False) -> dict:
        # A sip indicator with some defaults defined.
        if not tags or not isinstance(tags, list):
            tags = []
        if "ThreatFox" not in tags:
            tags.append("ThreatFox")
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

def yield_attractive_threatfox_iocs(filter_map: dict, iocs: List[dict]):
    """Filter ThreatFox IOCs.

    Filter by type, submitter, malware, confidence level, etc.

    Args:
      filter_map: Config describing malware IOCs to collect.
      ioc: An IOC to filter.
    Returns:
      True if we want to filter the IOC out. False if it should be skipped.
    """
    platforms = filter_map.get("platforms").split(',') if filter_map.get("platforms") else []
    require_malware_signature = filter_map.getboolean("require_malware_signature")
    malware_famlies = filter_map.get("malware").split(',') if filter_map.get("malware") else []
    threat_types = filter_map.get("threat_type").split(',') if filter_map.get("threat_type") else []
    confidence_level = filter_map.getint("confidence_level", 50)
    ioc_types = filter_map.get("ioc_type").split(',') if filter_map.get("ioc_type") else []
    accepted_reporters = filter_map.get("accepted_reporters").split(',') if filter_map.get("accepted_reporters") else []
    ignore_these_reporters = filter_map.get("ignore_these_reporters").split(',') if filter_map.get("ignore_these_reporters") else []

    # NOTE the list is reversed. If they change their app then it will break this collector.
    for ioc in iocs:
        ioc_platform = None
        if ioc.get("malware"):
            ioc_platform = ioc["malware"].split('.')[0] if '.' in ioc["malware"] else None

        if platforms:
            if not ioc_platform:
                #likely means the IOC doesn't have a malware family assigned
                logging.debug(f"skipping {ioc.get('id')}: ioc_platform not defined.")
                continue
            if ioc_platform not in platforms:
                logging.debug(f"skipping {ioc.get('id')}: {ioc_platform} not in {platforms}")
                continue
        if require_malware_signature and not ioc.get("malware"):
            logging.debug(f"skipping {ioc.get('id')}: does not have a malware family assigned.")
            continue
        if malware_famlies:
            if ioc.get("malware") and ioc.get("malware") not in malware_famlies:
                logging.debug(f"skipping {ioc.get('id')}: {ioc.get('malware')} not in {malware_famlies}")
                continue
        if threat_types:
            if ioc.get("threat_type") and ioc.get("threat_type") not in threat_types:
                logging.debug(f"skipping {ioc.get('id')}: {ioc.get('threat_type')} not in {threat_types}")
                continue
        if ioc["confidence_level"] < confidence_level:
            logging.debug(f"skipping {ioc.get('id')}: below confidence threshold.")
            continue
        if ioc_types and ioc["ioc_type"] not in ioc_types:
            logging.debug(f"skipping {ioc.get('id')}: not collecting this ioc type.")
            continue
        if accepted_reporters and ioc["reporter"] not in accepted_reporters:
            logging.debug(f"skipping {ioc.get('id')}: {ioc.get('reporter')} not in accepted reporters: {accepted_reporters}")
            continue
        if ignore_these_reporters and ioc["reporter"] in ignore_these_reporters:
            logging.debug(f"skipping {ioc.get('id')}: {ioc.get('reporter')} in ignored reporters: {ignore_these_reporters}")
            continue
        
        # good ioc
        yield ioc


async def collect(config):

    # variables
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

    # last collected IOC ID records the last successful IOC obtained from ThreatFox
    last_collected_ioc_id = 0
    last_collected_ioc_id_variable_path = os.path.join(HOME_PATH, "var", f"last_collected_ioc_id")
    if not os.path.exists(os.path.join(last_collected_ioc_id_variable_path)):
        logging.info(f"{last_collected_ioc_id_variable_path} doesn't exist.")
    else:
        try:
            with open(last_collected_ioc_id_variable_path, "r") as fp:
                last_collected_ioc_id = int(fp.read())
            logging.debug(f"last successful ioc collected from ThreatFox: {last_collected_ioc_id}")
        except Exception as e:
            logging.error(str(e))
            return False

    # max_indicators_per_day - keep a throttle on indicators created per day
    indicators_created_today = 0
    max_indicators_per_day = config['collection_settings'].getint('max_indicators_per_day')
    indicator_creation_count_file = os.path.join(HOME_PATH, 'var', f"indicator_count_for_{datetime.datetime.now().strftime('%Y-%m-%d')}")
    if not os.path.exists(indicator_creation_count_file):
        logging.info(f"reseting indicator count for a new day..")
        for old_file in glob.glob(f"{os.path.join(HOME_PATH, 'var')}/indicator_count_for_*"):
            logging.info(f"deleting old variable file: {old_file}")
            os.remove(old_file)
        with open(indicator_creation_count_file, 'w') as f:
            f.write(str(0))
    else:
        with open(indicator_creation_count_file, 'r') as f:
            indicators_created_today = f.read()
        indicators_created_today = int(indicators_created_today)

    if indicators_created_today >= max_indicators_per_day:
        logging.error(f"maximum indicators already created for the day.")

    # connect to sip
    sip = config["sip"].getboolean("enabled")
    if sip:
        verify_ssl = config['sip'].get('verify_ssl')
        if not os.path.exists(verify_ssl):
            verify_ssl=config['sip'].getboolean('verify_ssl')
        sip = pysip.Client(f"{config['sip'].get('server')}:{config['sip'].get('port')}", config['sip']['api_key'], verify=verify_ssl)
    create_domain_name_indicators_from_payload_urls = config["sip"].getboolean("create_domain_name_indicators_from_payload_urls")


    # For filtering IOCs by malware, confidence_level, submitter, etc.
    threatfox_ioc_filter = config["threatfox_ioc_filter"]

    # map ThreatFox IOCs to SIP IOCs
    sip_map = config['sip_mappings']

    # threatfox connection & collection settings
    api_key = config["threatfox"].get("api_key") if config["threatfox"].get("api_key") else None
    api_url = config["threatfox"].get("url") if config["threatfox"].get("url") else None

    indicators_created = 0

    # Check for incoming iocs that still need to be processing.
    ioc_paths = get_incoming_ioc_paths()
    logging.info(f"Found {len(ioc_paths)} incoming iocs...")
    if ioc_paths:
        iocs_from_storage = 0
        for ioc_path in ioc_paths:
            ioc = load_ioc(ioc_path)
            ioc_id = int(ioc["id"])
            # NOTE: not filtering IOCs again.
            # post to SIP
            ioc_type = ioc["ioc_type"]
            ioc_type = 'ip' if ioc_type == 'ip:port' else ioc_type
            if ioc_type == 'ip' and ":" in ioc['ioc']:
                ioc['ioc'] = ioc['ioc'].split(":")[0]
            itype = sip_map.get(ioc_type)
            if not itype:
                logging.debug(f"skipping {ioc_type}")
                continue
            ioc_reference = {_f:_v for _f,_v in ioc.items() if _f  in ['id', 'ioc_type_desc', 'reference', 'confidence_level', 'reporter', 'comment']}
            tags = []
            unique_tags = []
            if isinstance(ioc.get("tags"), list):
                for _t in ioc["tags"]:
                    if _t.lower() not in unique_tags:
                        unique_tags.append(_t.lower)
                        # capture the case
                        tags.append(_t)
            tags.append(ioc["malware_printable"])
            idata = format_indicator_for_sip(type=itype, value=ioc['ioc'], reference=ioc_reference, tags=tags, username=config['sip'].get('user'))
            if ioc["confidence_level"] == 100:
                idata["confidence"] = "high"
            if indicators_created_today >= max_indicators_per_day:
                logging.error(f"maximum indicators created for the day.")
                break
            try:
                result = create_sip_indicator(sip, idata) if sip else None
            except pysip.ConflictError:
                os.remove(ioc_path)
                continue
            if result:
                logging.info(f"created sip indictor ID={result}")
                iocs_from_storage += 1
                indicators_created += 1
                indicators_created_today += 1
                os.remove(ioc_path)
            # else: failed to post indicator to SIP

            if create_domain_name_indicators_from_payload_urls and ioc_type == "url" and ioc["threat_type"] == "payload_delivery":
                logging.debug(f"attempting to extract domain indicator from {ioc_id}")
                domain = urlparse(ioc['ioc']).netloc
                if not domain:
                    continue
                idata = format_indicator_for_sip(type='URI - Domain Name', value=domain, reference=ioc_reference, tags=tags, username=config['sip'].get('user'))
                try:
                    result = create_sip_indicator(sip, idata) if sip else None
                except pysip.ConflictError:
                    continue
                if result:
                    logging.info(f"created sip indictor ID={result}")
                    indicators_created += 1
                    indicators_created_today += 1

        logging.info(f"successfully posted {iocs_from_storage} to SIP.")

    process_from_storage_only = config["collection_settings"].getboolean("process_from_storage_only")
    if not process_from_storage_only:
        # get any new iocs
        total_ioc_count = 0
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
                # NOTE: We reverse the list as they come in from newest to oldest. Should we use the last_seen field instead?
                iocs.reverse()
                total_ioc_count = len(iocs)
                logging.debug(f"got {total_ioc_count} IOC results")
                # NOTE: filter IOCs here
                for ioc in yield_attractive_threatfox_iocs(threatfox_ioc_filter, iocs):
                    # let an error raise if the data changes
                    ioc_id = int(ioc["id"])
                    if ioc_id < last_collected_ioc_id:
                        logging.debug(f"already collected ThreatFox IOC: {ioc_id}")
                        continue
                    logging.debug(f"obtained new ioc id: {ioc_id}")
                    # post to SIP
                    ioc_type = ioc["ioc_type"]
                    ioc_type = 'ip' if ioc_type == 'ip:port' else ioc_type
                    if ioc_type == 'ip' and ":" in ioc['ioc']:
                        ioc['ioc'] = ioc['ioc'].split(":")[0]
                    itype = sip_map.get(ioc_type)
                    if not itype:
                        logging.debug(f"skipping {ioc_type}")
                        continue
                    ioc_reference = {_f:_v for _f,_v in ioc.items() if _f  in ['id', 'ioc_type_desc', 'reference', 'confidence_level', 'reporter', 'comment']}
                    tags = []
                    unique_tags = []
                    if isinstance(ioc.get("tags"), list):
                        for _t in ioc["tags"]:
                            if _t.lower() not in unique_tags:
                                unique_tags.append(_t.lower)
                                # capture the case
                                tags.append(_t)
                    tags.append(ioc["malware_printable"])
                    idata = format_indicator_for_sip(type=itype, value=ioc['ioc'], reference=ioc_reference, tags=ioc["tags"], username=config['sip'].get('user'))
                    sip_result = False
                    if indicators_created_today < max_indicators_per_day:
                        try:
                            sip_result = create_sip_indicator(sip, idata) if sip else None
                        except pysip.ConflictError:
                            continue
                        if sip_result:
                            logging.info(f"created sip indictor ID={sip_result}")
                            last_collected_ioc_id = ioc_id
                            indicators_created += 1
                            indicators_created_today += 1
                    else:
                        logging.warning(f"maximum indicators created for the day.")

                    if not sip_result:
                        # SIP post failed or max indicators created for the day, write locally to get picked back up later.
                        with open(os.path.join(STORED_DIR, f"{ioc_id}.json"), "w") as fp:
                            fp.write(json.dumps(ioc))
                            last_collected_ioc_id = ioc_id
                            indicators_stored += 1
                        continue

                    if create_domain_name_indicators_from_payload_urls and ioc_type == "url" and ioc["threat_type"] == "payload_delivery":
                        logging.debug(f"attempting to extract domain indicator from {ioc_id}")
                        domain = urlparse(ioc['ioc']).netloc
                        if not domain:
                            continue
                        idata = format_indicator_for_sip(type='URI - Domain Name', value=domain, reference=ioc_reference, tags=ioc["tags"], username=config['sip'].get('user'))
                        try:
                            result = create_sip_indicator(sip, idata) if sip else None
                        except pysip.ConflictError:
                            continue
                        if result:
                            logging.info(f"created sip indictor ID={result}")
                            indicators_created += 1
                            indicators_created_today += 1

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
    try:
        with open(indicator_creation_count_file, 'w') as fp:
            fp.write(str(indicators_created_today))
    except Exception as e:
        logging.error(f"Problem writing indicator count file: {e}")


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
    parser.add_argument(
        "-s",
        "--single-execution",
        action="store_true",
        default=False,
        help="If true, the collector will execute once and exit instead of starting the collection loop.",
    )
    parser.add_argument(
        "-pl",
        "--process-local-storage-only",
        action="store_true",
        default=False,
        help="If true, only locally stored ThreatFox IOCs will be processed. ThreatFox will not be queried for new IOCs.",
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

    if args.process_local_storage_only:
        config["collection_settings"]["process_from_storage_only"] = "yes"

    await collect(config)
    return True

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        write_error_report("uncaught exception: {0}".format(str(e)))
