#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import log_analyzer


class LogAnalyzerTest(unittest.TestCase):

    def test_get_latest_log_log_not_exist(self):
        nolog_dir = './tests/no_log'
        with self.assertRaisesRegexp(OSError, 'Logfile not found') as cm:
            log_analyzer.get_latest_log(nolog_dir)

    def test_get_latest_log_logdir_not_exist(self):
        nolog_dir = './tests/nologdir'
        with self.assertRaisesRegexp(OSError, "Logdir '{}' not found".format(nolog_dir)) as cm:
            log_analyzer.get_latest_log(nolog_dir)

    def test_get_latest_log_correct_logfile(self):
        log_dir = './tests/log'
        logfile = log_analyzer.get_latest_log(log_dir)
        self.assertEqual(logfile.filename, './tests/log/nginx-access-ui.log-20170704.log')

    def test_get_perurl_stats_too_many_erros(self):
        logfile = './tests/log/nginx-access-ui.log-20170704.log'
        extension = 'log'
        with self.assertRaisesRegexp(Exception, "Too many errors in parsing logfile."):
            log_analyzer.get_perurl_stats(log_analyzer.parse_logfile(logfile, extension), 5)

    def test_get_perurl_stats_count_urls(self):
        logfile = './tests/log/nginx-access-ui.log-20170704.log'
        extension = 'log'
        urls_dict, requests_s_count, request_time_sum = log_analyzer.get_perurl_stats(
            log_analyzer.parse_logfile(logfile, extension),
            20)
        self.assertEqual(len(urls_dict), 4)
        self.assertEqual(requests_s_count, 9)
        self.assertEqual(request_time_sum, 9)
        table = log_analyzer.generate_stats(urls_dict, requests_s_count, request_time_sum)
        self.assertEqual(len(table), 4)

    def test_median(self):
        self.assertEqual(log_analyzer.median([5, 17, 3, 9, 14, 2]), 7)
        self.assertEqual(log_analyzer.median([5, 2, 18, 8, 3]), 5)


if __name__ == '__main__':
    unittest.main()
