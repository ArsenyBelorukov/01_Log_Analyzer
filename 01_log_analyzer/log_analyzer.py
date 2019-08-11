#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

from __future__ import print_function
import logging
from string import Template
from collections import namedtuple, defaultdict
import datetime
import re
import argparse
import os
import json
import gzip


config = {
    "REPORT_SIZE": 100,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "PARSE_ERROR_LIMIT": 1,
    "PRECISION": 3,
    "REPORT_FILENAME_TEMPLATE": "report-%Y.%m.%d.html",
    "REPORT_TEMPLATE": "report.html",
    "SORT_FIELD": 'time_med'
}

RE_LOGNAME_PATTERN = re.compile("^nginx-access-ui.log-(?P<date>[0-9]{8}).(?P<ext>(gz|log))$")
RE_LOGLINE_PATTERN = re.compile('(?P<remote_addr>.+) '
                                '(?P<remote_user>.+)  '
                                '(?P<http_x_real_ip>.+) '
                                '\[(?P<time_local>.+)\] '
                                '"(?P<request>.+)" '
                                '(?P<status>\d+) '
                                '(?P<body_bytes_sent>\d+) '
                                '"(?P<http_referer>.*)" '
                                '"(?P<http_user_agent>.*)" '
                                '"(?P<http_x_forwarded_for>.*)" '
                                '"(?P<http_X_REQUEST_ID>.*)" '
                                '"(?P<http_X_RB_USER>.*)" '
                                '(?P<request_time>.+)')


LogFile = namedtuple('LogFile', ['filename', 'date', 'extension'])
ParsedLine = namedtuple('ParsedLine', ['url', 'request_time'])


def get_config(config_path):
    if not os.path.isfile(config_path):
        raise OSError("Config '{}' not found".format(config_path))
    try:
        with open(config_path) as f:
            l_config = json.load(f)
    except ValueError as ex:
        raise ValueError("Can't parse config {}. {}".format(config_path, ex.message))
    r_config = config.copy()
    r_config.update(l_config)
    return r_config


def parse_logfile(logfile_name, extension):
    opener = gzip.open if extension == 'gz' else open
    with opener(logfile_name) as f:
        for line in f:
            remath = RE_LOGLINE_PATTERN.match(line)
            if not remath:
                yield None
            else:
                url = remath.group('request').split(' ', 1)[-1].rsplit(' ', 1)[0]
                yield ParsedLine(url, remath.group('request_time'))


def get_latest_log(log_dir):
    if not os.path.isdir(log_dir):
        raise OSError("Logdir '{}' not found".format(log_dir))
    logfile_filename = None
    logfile_date = None
    logfile_extension = None
    date_format = "%Y%m%d"
    for lfile in os.listdir(log_dir):
        remath = RE_LOGNAME_PATTERN.match(lfile)
        if not remath:
            continue
        else:
            try:
                lfile_date = datetime.datetime.strptime(remath.group('date'), date_format)
            except:
                logging.info("Can't parse date in '{}'".format(lfile))
                continue
            if logfile_date is None or lfile_date > logfile_date:
                logfile_date = lfile_date
                logfile_filename = lfile
                logfile_extension = remath.group('ext')
    if logfile_filename is None:
        raise OSError("Logfile not found")
    return LogFile(os.path.join(log_dir, logfile_filename), logfile_date, logfile_extension)


def parse_args():
    parser = argparse.ArgumentParser(description="Log analyzer for nginx logs")
    parser.add_argument("--config",
                        action='store',
                        help="Path to custom config file",
                        default='./log_analyzer.json')
    return parser.parse_args()


def check_report_exist(report_dir, report_date, report_filename):
    return os.path.isfile(os.path.join(report_dir,
                      report_date.strftime(report_filename)))


def median(vallist):
    tmp = sorted(vallist)
    l_tmp = len(tmp)
    if l_tmp % 2 == 0:
        return (tmp[l_tmp//2-1] + tmp[l_tmp//2])/float(2)
    else:
        return tmp[l_tmp//2]


def generate_stats(urls_dict, requests_s_count, request_time_sum):
    table = []
    for url, request_times in urls_dict.items():
        req_count = len(request_times)
        time_sum = sum(request_times)
        table.append({
            "url": url,
            "count": req_count,
            "count_perc": 100 * float(req_count) / requests_s_count,
            "time_sum": time_sum,
            "time_perc": 100 * float(time_sum) / request_time_sum,
            "time_avg": float(time_sum) / req_count,
            "time_max": max(request_times),
            "time_med": median(request_times),
        })
    return table


def generate_report(table, report_filename, report_template):
    with open(report_template) as f:
        tmplt = Template(f.read())
    with open(report_filename, 'w') as f:
        f.write(tmplt.safe_substitute(table_json=table))


def get_perurl_stats(parsed_lines, PRECISION):
    urls_dict = defaultdict(list)
    requests_s_count = 0
    requests_f_count = 0
    request_time_sum = 0
    logging.info("Start parsing logfile")
    for parsed_line in parsed_lines:
        if parsed_line is None:
            requests_f_count += 1
            continue
        requests_s_count += 1
        request_time_sum += float(parsed_line.request_time)
        urls_dict[parsed_line.url].append(float(parsed_line.request_time))
    if float(requests_f_count) / (requests_s_count + requests_f_count) * 100 > PRECISION:
        raise Exception("Too many errors in parsing logfile.")
    return urls_dict, requests_s_count, request_time_sum


def main():
    args = parse_args()
    config = get_config(args.config)
    logfile = config.get("LOG")
    FORMAT = '[%(asctime)s] %(levelname).1s %(message)s'
    logging.basicConfig(format=FORMAT, filename=logfile, level=logging.INFO)
    if not os.path.exists(os.path.abspath(config['REPORT_DIR'])):
        os.mkdir(os.path.abspath(config['REPORT_DIR']))
    # if not os.path.isfile(os.path.join(os.path.abspath(config['REPORT_DIR']), config['REPORT_TEMPLATE'])):
    #     raise OSError("Template report.html not found")
    logfile = get_latest_log(os.path.abspath(config['LOG_DIR']))
    logging.info("Found latest logfile {}".format(logfile.filename))
    if check_report_exist(os.path.abspath(config['REPORT_DIR']), logfile.date, config['REPORT_FILENAME_TEMPLATE'],):
        raise Exception("Report for {} already exist".format(logfile.date.date()))
    urls_dict, requests_s_count, request_time_sum = get_perurl_stats(parse_logfile(logfile.filename, logfile.extension),
                                                                      config['PRECISION'])
    logging.info("Start calculating statistics")
    table = generate_stats(urls_dict, requests_s_count, request_time_sum)
    table = table if len(table) <= config['REPORT_SIZE'] \
        else sorted(table, key=lambda x: x[config['SORT_FIELD']])[-config['REPORT_SIZE']:]
    logging.info("Start generating report")
    report_filename = os.path.join(os.path.abspath(config['REPORT_DIR']), logfile.date.strftime(config['REPORT_FILENAME_TEMPLATE']))
    generate_report(table, report_filename, os.path.join(os.path.abspath(config['REPORT_DIR']), config['REPORT_TEMPLATE']))
    logging.info("Report {} was successfully generated".format(report_filename))


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        logging.exception("{} finished with error. {}".format(__file__, str(ex)), exc_info=True)