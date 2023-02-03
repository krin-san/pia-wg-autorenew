import json
import logging
import os
import time
from datetime import datetime

from piawg import piawg


REQUIRED_KEYS = {
    "USERNAME" : str,
    "PASSWORD" : str,
    "UPDATE_INTERVAL" : int,
    "REGION" : str
}
WG_CONFIG_FILE='/app/wg{}.conf'
CONNECTION_DETAILS_FILE='/app/connection{}.env'


class PiaWGDaemon:
    def __init__(self):
        logging.basicConfig(level=logging.DEBUG, format='%(name)s - %(levelname)s - %(message)s')

        self.config = {}
        self.config["CONFIG_COUNT"] = int(os.environ.get("CONFIG_COUNT", "1"))

        for key in REQUIRED_KEYS:
            current_param = os.environ.get(key)

            if current_param is None:
                error_msg = "{} key was not found in the environment".format(key)

                logging.error(error_msg)
                raise KeyError(error_msg)

            if not isinstance(current_param, REQUIRED_KEYS[key]):
                found_type = type(current_param)
                try:
                    current_param = REQUIRED_KEYS[key](current_param)
                except:
                    error_msg = "{} key was of a wrong type. Found: {} Expected: {}".format(
                        key,
                        found_type,
                        REQUIRED_KEYS[key]
                    )

                    logging.error(error_msg)
                    raise KeyError(error_msg)

            self.config[key] = current_param

        pia = piawg()
        pia.set_region(self.config["REGION"])

        self.loop_delay = 5
        self.last_config_update = 0

    def event_loop(self):
        logging.info("Starting event loop...")
        try:
            while True:
                if self.last_config_update != 0 and time.monotonic() - self.last_config_update < self.config["UPDATE_INTERVAL"]:
                    time.sleep(self.loop_delay)
                    continue

                logging.info("Updating configs...")
                for index in range(self.config["CONFIG_COUNT"]):
                    pia = piawg()
                    pia.set_region(self.config["REGION"])
                    self.update_wireguard_config(pia, index)

        except KeyboardInterrupt:
            logging.info("Event Loop Interrupted, exiting")
            exit()

    def update_wireguard_config(self, pia, index):
        logging.info("Updating Token")

        pia.generate_keys()

        if pia.get_token(self.config["USERNAME"], self.config["PASSWORD"]):
            successful_login = True
            logging.info("Login Successful")
        else:
            logging.error("Error Logging In")
            successful_login = False

        self.last_config_update = time.monotonic()

        if not successful_login:
            return

        status, response = pia.add_key()

        if status:
            logging.info("Added key to server!")
        else:
            logging.error("Error adding key to server")
            logging.error(response)
            return

        self.write_file(pia, index)

    def write_file(self, pia, index):
        logging.info("Writing Wireguard config")

        with open(WG_CONFIG_FILE.format(index), 'w+') as file:
            file.write('[Interface]\n')
            file.write('Address = {}\n'.format(pia.connection['peer_ip']))
            file.write('PrivateKey = {}\n'.format(pia.private_key))
            file.write('DNS = {},{}\n\n'.format(pia.connection['dns_servers'][0], pia.connection['dns_servers'][1]))
            file.write('[Peer]\n')
            file.write('PublicKey = {}\n'.format(pia.connection['server_key']))
            file.write('Endpoint = {}:1337\n'.format(pia.connection['server_ip']))
            file.write('AllowedIPs = 0.0.0.0/0\n')
            file.write('PersistentKeepalive = 25\n')

        with open(CONNECTION_DETAILS_FILE.format(index), 'w+') as file:
            cn, ip = pia.wireguard_server()
            file.write('PF_GATEWAY="{}"\n'.format(ip))
            file.write('PF_HOSTNAME="{}"\n'.format(cn))
            file.write('PIA_TOKEN="{}"\n'.format(pia.token))


if __name__ == "__main__":
    PiaWGDaemon().event_loop()
