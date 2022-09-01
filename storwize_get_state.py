#!/bin/python3
# -*- coding: utf-8 -*-
import time
import argparse
import sys
import json
import subprocess
import logging
import logging.handlers
import csv
import re
import warnings


# Create log-object
LOG_FILENAME = "/tmp/storwize_state.log"
# sys.argv[5] contain this string "--storage_name=<storage_name_in_zabbix>". List slicing delete this part "--storage_name="
STORAGE_NAME = sys.argv[5][15:]
storwize_logger = logging.getLogger("storwize_logger")
storwize_logger.setLevel(logging.INFO)

# Set handler
storwize_handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=(1024**2)*10, backupCount=5)
storwize_formatter = logging.Formatter('{0} - %(asctime)s - %(name)s - %(levelname)s - %(message)s'.format(STORAGE_NAME))

# Set formatter for handler
storwize_handler.setFormatter(storwize_formatter)

# Add handler to log-object
storwize_logger.addHandler(storwize_handler)


def storwize_logout(ssh_client):
    try:
        ssh_client.close()
        storwize_logger.info("Connection Closed Successfully")
    except Exception as e:
        storwize_logger.exception(f"Connection Close Error Occurs: {e}")
        sys.exit("1000")


def convert_to_zabbix_json(data):
    output = json.dumps({"data": data}, indent=None, separators=(',', ':'))
    return output


def convert_text_to_numeric(value: str):
    value_to_code = dict(
        online=0, offline=1, degraded=2, active=3, inactive_configured=4, inactive_unconfigured=5,
        offline_unconfigured=6, excluded=7, on=8, off=9, slow_flashing=10, degraded_paths=11, degraded_ports=12
    )
    return value_to_code.get(value) or 100


def advanced_info_of_resource(resource: str, needed_attributes, storwize_connection, *id_of_resource):
    """
    :param needed_attributes: list of parameters, that we want to get.
    :param id_of_resource: list of additional parameters, that uniquely determine resource.
    Example: for PSU - first element of list is enclosure_id, secondary element of list is PSU_id"""
    if resource == 'lsenclosure':
        stdin, stdout, stderr = storwize_connection.exec_command('svcinfo {0} {1}'.format(resource, id_of_resource[0]))
    elif resource == 'lsenclosurepsu':
        stdin, stdout, stderr = storwize_connection.exec_command('svcinfo {0} -psu {1} {2}'.format(resource, id_of_resource[1], id_of_resource[0]))

    if len(stderr.read()) > 0:
        storwize_logger.info("Error Occurs in advanced info of enclosure - {0}".format(stderr.read()))
        storwize_logout(storwize_connection)
        sys.exit("1100")
    else:
        # Получили расширенные атрибуты в виде строки (variable contain advanced attributes in string)
        attributes_of_resource = stdout.read()
        # Здесь будут храниться расширенные атрибуты ресурса в формате ключ-значение
        # (will contain advanced attributes in key-value)
        dict_of_attributes = {}
        try:
            # Разделил строку и получили список из расширенные атрибутов
            for attribute in attributes_of_resource.split('\n'):
                if len(attribute) > 0:
                    temp = attribute.split(' ')
                    dict_of_attributes[temp[0]] = temp[1]
        except Exception as oops:
            storwize_logger.error("Error occurs in function advanced_info_of_resource - {0}".format(oops))
            storwize_logout(storwize_connection)
            sys.exit("1100")

    # Создаем словарь из необходимых нам свойств ресурса (create dictionary that contain properties of resource)
    result = {}
    for each_value in needed_attributes:
        result[each_value] = dict_of_attributes[each_value]

    return result


def convert_capacity_to_bytes(capacity_in_string):
    """ Конвертирует значение, которое отдает СХД в виде строки, в байты
        Convert value, from string to byte, that get from storage device
    """
    convert_to_bytes = {'TB': 1024**4, 'GB': 1024**3, 'MB': 1024**2, 'KB': 1024}
    try:
        # Ищем по регулярному выражению и находим две группы совпадения
        list_of_capacity = re.search(r'([\d.]+)(\D+)', capacity_in_string)
        converted_capacity = float(list_of_capacity.group(1)) * convert_to_bytes[list_of_capacity.group(2)]
        # Конвертация в целые числа, потому что для float в Заббиксе есть ограничение (convert to type integer)
        return int(converted_capacity)
    except Exception:
        storwize_logger.exception("Error occurs in converting capacity_in_string to capacity_in_bytes")


def send_data_to_zabbix(zabbix_data, storage_name) -> int:
    sender_command = "/usr/bin/zabbix_sender"
    config_path = "/etc/zabbix/zabbix_agentd.conf"

    send_code = subprocess.run(
        [sender_command, "-vv", "-c", config_path, "-s", storage_name, "-T", "-i", "-"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', input='\n'.join(zabbix_data)
    )
    return send_code.returncode


def discovering_resources(storwize_connection, storage_name, list_resources):
    xer = []
    try:
        for resource in list_resources:
            stdin, stdout, stderr = storwize_connection.exec_command('svcinfo {0} -delim :'.format(resource))

            # Если случились ошибки, запиши их в лог и выйди из скрипта
            # (If errors occur, than write them to log and correctly end of ssh-session)
            if len(stderr.read()) > 0:
                storwize_logger.info("Error Occurs in SSH Command - {0}".format(stderr.read()))
                storwize_logout(storwize_connection)
                sys.exit("1100")
            else:
                resource_in_csv = csv.DictReader(stdout, delimiter=':')  # Create CSV

                discovered_resource = []
                storwize_logger.info("Starting discovering resource - {0}".format(resource))
                for one_object in resource_in_csv:
                    if ['lsvdisk', 'lsmdisk', 'lsmdiskgrp'].count(resource) == 1:
                        one_object_list = {"{#ID}": one_object["id"], "{#NAME}": one_object["name"]}
                        discovered_resource.append(one_object_list)
                    elif ['lsenclosurebattery', 'lsenclosurepsu', 'lsenclosurecanister'].count(resource) == 1:
                        one_object_list = {"{#ENCLOSURE_ID}": one_object["enclosure_id"]}
                        if resource == 'lsenclosurebattery':
                            one_object_list["{#BATTERY_ID}"] = one_object["battery_id"]
                        if resource == 'lsenclosurepsu':
                            one_object_list["{#PSU_ID}"] = one_object["PSU_id"]
                        if resource == 'lsenclosurecanister':
                            one_object_list["{#CANISTER_ID}"] = one_object["canister_id"]
                        discovered_resource.append(one_object_list)
                    elif ['lsportfc', 'lsportsas'].count(resource) == 1:
                        one_object_list = {"{#PORT_ID}": one_object["port_id"], "{#NODE_NAME}": one_object["node_name"]}
                        discovered_resource.append(one_object_list)
                    elif ['lsenclosure'].count(resource) == 1:
                        one_object_list = {"{#ID}": one_object["id"], "{#MTM}": one_object["product_MTM"],
                                           "{#SERIAL_NUMBER}": one_object["serial_number"]}
                        discovered_resource.append(one_object_list)
                    elif ['lsdrive'].count(resource) == 1:
                        one_object_list = {"{#ENCLOSURE_ID}": one_object["enclosure_id"],
                                           "{#SLOT_ID}": one_object["slot_id"]}
                        discovered_resource.append(one_object_list)
                    else:
                        one_object_list = {"{#ID}": one_object["id"], "{#ENCLOSURE_ID}": one_object["enclosure_id"]}
                        discovered_resource.append(one_object_list)

                storwize_logger.info("Success get resource - {0}".format(resource))

                converted_resource = convert_to_zabbix_json(discovered_resource)
                xer.append(f"{storage_name} {resource} {int(time.time())} {converted_resource}")
    except Exception as e:
        storwize_logger.exception(f"Error occurs in discovering - {e}")
        storwize_logout(storwize_connection)
        sys.exit("1100")

    storwize_logout(storwize_connection)
    return send_data_to_zabbix(xer, storage_name)


def get_status_resources(storwize_connection, storage_name, list_resources):
    # В этот список будут складываться состояние каждого ресурса (диск, блок питания, ...) в формате Zabbix
    # (This list will contain state of every resource (disk, psu, ...) on zabbix format)
    state_resources = []
    is_there_expansion_enclosure = 0

    try:
        for resource in list_resources:
            stdin, stdout, stderr = storwize_connection.exec_command('svcinfo {0} -delim :'.format(resource))

            # Если случились ошибки, запиши их в лог и выйди из скрипта
            # (If errors occur, then write them to log-file and correctyly end of ssh-session)
            if len(stderr.read()) > 0:
                storwize_logger.error("Error Occurs in SSH Command - {0}".format(stderr.read()))
                storwize_logout(storwize_connection)
                sys.exit("1100")
            else:
                resource_in_csv = csv.DictReader(stdout, delimiter=':')  # Create CSV
                timestamp_now = int(time.time())
                storwize_logger.info("Starting collecting status of resource - {0}".format(resource))

                for one_object in resource_in_csv:
                    if ['lsmdiskgrp'].count(resource) == 1:
                        key_health = "health.{0}.[{1}]".format(resource, one_object["name"])
                        key_overallocation = "overallocation.{0}.[{1}]".format(resource, one_object["name"])
                        key_used = "used.{0}.[{1}]".format(resource, one_object["name"])
                        key_virtual = "virtual.{0}.[{1}]".format(resource, one_object["name"])
                        key_real = "real.{0}.[{1}]".format(resource, one_object["name"])
                        key_free = "free.{0}.[{1}]".format(resource, one_object["name"])
                        key_total = "total.{0}.[{1}]".format(resource, one_object["name"])

                        state_resources.append("%s %s %s %s" % (storage_name, key_health, timestamp_now, convert_text_to_numeric(one_object["status"])))
                        state_resources.append("%s %s %s %s" % (storage_name, key_overallocation, timestamp_now, one_object["overallocation"]))
                        state_resources.append("%s %s %s %s" % (storage_name, key_used, timestamp_now, convert_capacity_to_bytes(one_object["used_capacity"])))
                        state_resources.append("%s %s %s %s" % (storage_name, key_virtual, timestamp_now, convert_capacity_to_bytes(one_object["virtual_capacity"])))
                        state_resources.append("%s %s %s %s" % (storage_name, key_real, timestamp_now, convert_capacity_to_bytes(one_object["real_capacity"])))
                        state_resources.append("%s %s %s %s" % (storage_name, key_free, timestamp_now, convert_capacity_to_bytes(one_object["free_capacity"])))
                        state_resources.append("%s %s %s %s" % (storage_name, key_total, timestamp_now, convert_capacity_to_bytes(one_object["capacity"])))

                    elif ['lsenclosurecanister'].count(resource) == 1:
                        key_health = "health.{0}.[{1}.{2}]".format(resource, one_object["enclosure_id"], one_object["canister_id"])
                        state_resources.append("%s %s %s %s" % (storage_name, key_health, timestamp_now, convert_text_to_numeric(one_object["status"])))
                    elif ['lsenclosurebattery'].count(resource) == 1:
                        key_health = "health.{0}.[{1}.{2}]".format(resource, one_object["enclosure_id"], one_object["battery_id"])
                        state_resources.append("%s %s %s %s" % (storage_name, key_health, timestamp_now, convert_text_to_numeric(one_object["status"])))
                    elif ['lsdrive'].count(resource) == 1:
                        key_health = "health.{0}.[{1}.{2}]".format(resource, one_object["enclosure_id"], one_object["slot_id"])
                        state_resources.append("%s %s %s %s" % (storage_name, key_health, timestamp_now, convert_text_to_numeric(one_object["status"])))
                    elif ['lsenclosurepsu'].count(resource) == 1:
                        needed_attributes = ['input_failed', 'output_failed', 'fan_failed']
                        enclosure_id = one_object["enclosure_id"]
                        psu_id = one_object["PSU_id"]
                        advanced_info = advanced_info_of_resource(resource, needed_attributes, storwize_connection, enclosure_id, psu_id)

                        key_input_failed = "inFailed.{0}.[{1}.{2}]".format(resource, one_object["enclosure_id"], one_object["PSU_id"])
                        key_output_failed = "outFailed.{0}.[{1}.{2}]".format(resource, one_object["enclosure_id"], one_object["PSU_id"])
                        key_fan_failed = "fanFailed.{0}.[{1}.{2}]".format(resource, one_object["enclosure_id"], one_object["PSU_id"])
                        key_health = "health.{0}.[{1}.{2}]".format(resource, one_object["enclosure_id"], one_object["PSU_id"])
                        state_resources.append("%s %s %s %s" % (storage_name, key_health, timestamp_now, convert_text_to_numeric(one_object["status"])))
                        state_resources.append("%s %s %s %s" % (storage_name, key_input_failed, timestamp_now, convert_text_to_numeric(advanced_info["input_failed"])))
                        state_resources.append("%s %s %s %s" % (storage_name, key_output_failed, timestamp_now, convert_text_to_numeric(advanced_info["output_failed"])))
                        state_resources.append("%s %s %s %s" % (storage_name, key_fan_failed, timestamp_now, convert_text_to_numeric(advanced_info["fan_failed"])))
                    elif ['lsenclosure'].count(resource) == 1:
                        needed_attributes = ['fault_LED']
                        enclosure_id = one_object["id"]
                        advanced_info = advanced_info_of_resource(resource, needed_attributes, storwize_connection, enclosure_id)

                        key_fault_led = "faultLED.{0}.[{1}.{2}]".format(resource, one_object["id"], one_object["serial_number"])
                        key_health = "health.{0}.[{1}.{2}]".format(resource, one_object["id"], one_object["serial_number"])
                        state_resources.append(f"{storage_name} {key_health} {timestamp_now} {convert_text_to_numeric(one_object['status'])}")
                        state_resources.append(f"{storage_name} {key_fault_led} {timestamp_now} {convert_text_to_numeric(advanced_info['fault_LED'])}")

                        if one_object["type"] == "expansion":
                            is_there_expansion_enclosure += 1

                    elif ['lsportfc', 'lsportsas'].count(resource) == 1:
                        key_running = "running.{0}.[{1}.{2}]".format(resource, one_object["port_id"], one_object["node_name"])
                        state_resources.append(f"{storage_name} {key_running} {timestamp_now} {convert_text_to_numeric(one_object['status'])}")
                    elif ['lsvdisk', 'lsmdisk'].count(resource) == 1:
                        key_health = "health.{0}.[{1}]".format(resource, one_object["name"])
                        state_resources.append(f"{storage_name} {key_health} {timestamp_now} {convert_text_to_numeric(one_object['status'])}")

                state_resources.append(f"{storage_name} is_there_expansion_enclosure {timestamp_now} {is_there_expansion_enclosure}")
    except Exception as e:
        storwize_logger.exception(f"Error occurs in collecting status - {e}")
        # Если возникло исключение, нужно корректно завершить ssh-сессию
        # (If exception occur, than correctly end of ssh-session)
        storwize_logout(storwize_connection)
        sys.exit("1100")

    # Завершаем ssh-сессию при успешном выполнении сбора метрик (Correctly end of session after get metrics)
    storwize_logout(storwize_connection)
    return send_data_to_zabbix(state_resources, storage_name)


def main():
    storwize_parser = argparse.ArgumentParser()
    storwize_parser.add_argument('--storwize_ip', type=str, help="IP address to connect", required=True)
    storwize_parser.add_argument('--storwize_port', type=int, default=22,
                                 help="SSH port to connect (default: %(default)s)")
    storwize_parser.add_argument('--storwize_user', action="store", required=True)
    storwize_parser.add_argument('--storwize_password', action="store", required=True)
    storwize_parser.add_argument('--storage_name', action="store", required=True)

    group = storwize_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--discovery', action='store_true')
    group.add_argument('--status', action='store_true')

    storwize_parser.add_argument('--suppress_paramiko_warnings', action='store_true',
                                 help='Do not output any warnings in stderr')

    arguments = storwize_parser.parse_args()

    list_resources = ['lsvdisk', 'lsmdisk', 'lsmdiskgrp', 'lsenclosure', 'lsenclosurebattery', 'lsenclosurepsu',
                      'lsenclosurecanister', 'lsdrive', 'lsportfc', 'lsportsas']

    if arguments.suppress_paramiko_warnings:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            import paramiko
    else:
        import paramiko

    # Установление SSH-соединения
    try:
        storwize_connection = paramiko.SSHClient()
        storwize_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        storwize_connection.connect(
            hostname=arguments.storwize_ip, port=arguments.storwize_port,
            username=arguments.storwize_user, password=arguments.storwize_password
        )
        storwize_logger.info("Connection Established Successfully")
    except Exception as e:
        storwize_logger.exception(f"Connection error: {e}")
        sys.exit("1000")

    if arguments.discovery:
        storwize_logger.info("********************************* Starting Discovering *********************************")
        result_discovery = discovering_resources(storwize_connection, arguments.storage_name, list_resources)
        print(result_discovery)
    elif arguments.status:
        storwize_logger.info("********************************* Starting Get Status *********************************")
        result_status = get_status_resources(storwize_connection, arguments.storage_name, list_resources)
        print(result_status)


if __name__ == "__main__":
    main()
