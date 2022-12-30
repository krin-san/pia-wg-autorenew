import json
import requests
import subprocess
import urllib.parse
import urllib3
from requests_toolbelt.adapters import host_header_ssl


# PIA uses the CN attribute for certificates they issue themselves.
# This will be deprecated by urllib3 at some point in the future, and generates a warning (that we ignore).
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)


class piawg:
    def __init__(self):
        self.server_list = {}
        self.region = None
        self.token = None
        self.public_key = None
        self.private_key = None
        self.connection = None

        self.get_server_list()


    def __is_valid_response(self, response):
        return response.status_code == 200 and response.json()['status'] == 'OK'

    # Common name and IP address for metadata endpoint in region
    def meta_server(self):
        server = self.server_list[self.region]['servers']['meta'][0]
        return server['cn'], server['ip']

    # Common name and IP address for wireguard endpoint in region
    def wireguard_server(self):
        server = self.server_list[self.region]['servers']['wg'][0]
        return server['cn'], server['ip']

    def __verified_session(self):
        # Some tricks to verify PIA certificate, even though we're sending requests to an IP and not a proper domain
        # https://toolbelt.readthedocs.io/en/latest/adapters.html#requests_toolbelt.adapters.host_header_ssl.HostHeaderSSLAdapter
        session = requests.Session()
        session.mount('https://', host_header_ssl.HostHeaderSSLAdapter())
        session.verify = 'ca.rsa.4096.crt'
        return session

    def get_server_list(self):
        r = requests.get('https://serverlist.piaservers.net/vpninfo/servers/v4')
        # Only process first line of response, there's some base64 data at the end we're ignoring
        data = json.loads(r.text.splitlines()[0])
        for server in data['regions']:
            self.server_list[server['id']] = server

    def set_region(self, region_id):
        if region_id not in self.server_list.keys():
            raise KeyError('Region "{}" is not a valid one'.format(region_id))

        self.region = region_id

    def get_token(self, username, password):
        cn, ip = self.meta_server()
        r = self.__verified_session().get(
            "https://{}/authv3/generateToken".format(ip),
            headers={"Host": cn},
            auth=(username, password)
        )

        if self.__is_valid_response(r):
            self.token = r.json()['token']
            return True
        else:
            return False

    def generate_keys(self):
        self.private_key = subprocess.run(
            ['wg', 'genkey'],
            stdout=subprocess.PIPE,
            encoding="utf-8"
        ).stdout.strip()
        self.public_key = subprocess.run(
            ['wg', 'pubkey'],
            input=self.private_key,
            stdout=subprocess.PIPE,
            encoding="utf-8"
        ).stdout.strip()

    def add_key(self):
        cn, ip = self.wireguard_server()
        r = self.__verified_session().get(
            "https://{}:1337/addKey?pt={}&pubkey={}".format(
                ip,
                urllib.parse.quote(self.token),
                urllib.parse.quote(self.public_key)
            ),
            headers={"Host": cn}
        )

        if self.__is_valid_response(r):
            self.connection = r.json()
            return True, r.content
        else:
            return False, r.content
