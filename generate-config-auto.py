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
WG_CONFIG_FILE='/app/wg0.conf'


class PiaWGDaemon:
    def __init__(self):
        logging.basicConfig(level=logging.DEBUG, format='%(name)s - %(levelname)s - %(message)s')

        self.config = {}

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
        try:
            while True:
                if time.monotonic() - self.last_config_update < self.config["UPDATE_INTERVAL"]:
                    time.sleep(self.loop_delay)
                    continue

                pia = piawg()
                pia.set_region(self.config["REGION"])
                self.update_wireguard_config(pia)

        except KeyboardInterrupt:
            logging.info("Event Loop Interrupted, exiting")
            exit()

    def update_wireguard_config(self, pia):
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

        self.write_file(pia)

    def write_file(self, pia):
        logging.info("Writing Wireguard config")

        with open(WG_CONFIG_FILE, 'w+') as file:
            file.write('[Interface]\n')
            file.write('Address = {}\n'.format(pia.connection['peer_ip']))
            file.write('PrivateKey = {}\n'.format(pia.private_key))
            file.write('DNS = {},{}\n\n'.format(pia.connection['dns_servers'][0], pia.connection['dns_servers'][1]))
            file.write('[Peer]\n')
            file.write('PublicKey = {}\n'.format(pia.connection['server_key']))
            file.write('Endpoint = {}:1337\n'.format(pia.connection['server_ip']))
            file.write('AllowedIPs = 0.0.0.0/0\n')
            file.write('PersistentKeepalive = 25\n')


if __name__ == "__main__":
    PiaWGDaemon().event_loop()
