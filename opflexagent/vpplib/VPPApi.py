#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""VPP API interface"""

import binascii
import json
import time

from opflexagent.vpplib.vpp_papi_provider import VppPapiProvider


def mac_to_bytes(mac):
    return str(''.join(chr(int(x, base=16)) for x in mac.split(':')))


class VppCtxt(object):
    def reconnect(self):
        _reconn_cnt = 0
        while not self.connected:
            self.vppp.disconnect()
            try:
                if _reconn_cnt >= 10:
                    raise SystemExit("Exceeded 30 retries connecting to VPP")
                else:
                    _reconn_cnt += 1
                rv = self.vppp.connect()
                if rv == 0:
                    self.connected = True
            except IOError:
                time.sleep(self.reconnect_interval)
                self.connected = False

    def __init__(self, client_name, LOG):
        self.client_name = client_name
        self.LOG = LOG
        self.read_timeout = 3
        self.reconnect_interval = 1
        self.vppp = None
        self.connected = False

    def __enter__(self):
        self.vppp = VppPapiProvider(self.client_name, None, self.read_timeout)
        self.reconnect()
        return self.vppp

    def __exit__(self, exc_type, exc, exc_tb):
        self.vppp.disconnect()
        return exc is None


class VPPApi(object):
    """General class for the VPP API provider methods/functions."""

    def __init__(self, log, client_name):
        """
        The VPPApi class.

        :param log: logger
        :type log: class
        """
        self.system_state = {}
        self.LOG = log
        self.client_name = client_name
        self.LOG.debug('')

    @staticmethod
    def _fix_tuplelist(tpl):
        """
        Fixes a string returned from the reply

        :param tpl: The tuple to be fixed
        :type tpl: list
        :return: The fixed tuple list it's a list of dictionaries
        """

        fixedtpl = []
        for tp in tpl:
            fixedtpl.append(tp._asdict())

        return fixedtpl

    @staticmethod
    def _fix_tag(istr):
        """
        Fixes a string returned from the reply

        :param istr: The string to be fixed
        :type istr: str
        :return: The fixed string
        """

        rstr = ''
        for i in bytearray(istr):
            if i is 0:
                return rstr
            rstr += chr(i)
        return rstr

    @staticmethod
    def _fix_v4_addr(iaddr):
        """
        Fixes a string returned from the reply

        :param iaddr: The address to be fixed
        :type iaddr: str
        :return: The fixed string
        """

        rstr = ''
        for i in range(4):
            rstr += '{}.'.format(bytearray(iaddr)[i])
        return rstr.rstrip('.')

    @staticmethod
    def _fix_l2_addr(iaddr, length):
        """
        Fixes a string returned from the reply

        :param iaddr: The address to be fixed
        :type iaddr: str
        :param length: The length of the address
        :type length: int
        :return: The fixed string
        """

        rstr = ''
        for i in range(length):
            rstr += '{:02x}:'.format(bytearray(iaddr)[i])
        return rstr.rstrip(':')

    @staticmethod
    def _fix_string(istr):
        """
        Fixes a string returned from the reply

        :param istr: The string to be fixed
        :type istr: str
        :return: The fixed string
        """

        rstr = ''
        for i in bytearray(istr):
            if i is 0:
                return rstr
            rstr += chr(i)

    def _handle_replylist(self, reply):
        """
        Handles a generic api reply

        :param reply: The api call reply
        :type reply: list
        :returns: The reply data in json
        """

        datalist = []
        for idx, details in enumerate(reply):
            # noinspection PyProtectedMember
            data = details._asdict()
            for i in list(data.items()):
                key = i[0]
                value = i[1]
                if type(value) is str:
                    value = self._fix_string(value)
                    data[key] = value
            datalist.append(data)

        try:
            jd = json.dumps(datalist)
        except Exception:
            self.LOG.error(reply)
            raise

        self.LOG.debug('{}'.format(jd))
        return jd

    def _handle_replytuple(self, reply):
        """
        Handles a generic api reply

        :param reply: The api call reply
        :type reply: tuple
        :returns: The reply data in json
        """

        # noinspection PyProtectedMember
        data = reply._asdict()
        for i in list(data.items()):
            key = i[0]
            value = i[1]
            if type(value) is str:
                value = self._fix_string(value)
                data[key] = value

        try:
            jd = json.dumps(data)
        except Exception:
            self.LOG.error(reply)
            raise

        self.LOG.debug('{}'.format(jd))
        return jd

    def _handle_reply(self, reply):
        """
        Handles a generic api reply

        :param reply: The api call reply
        :type reply: tuple or list
        :returns: The reply data in json
        """

        if type(reply) is list:
            return self._handle_replylist(reply)
        else:
            return self._handle_replytuple(reply)

    def _handle_vhost(self, reply):
        """
        Handles the vhost sw interface dump reply

        :param reply: The api call reply
        :type reply: list
        """

        datalist = []
        for idx, details in enumerate(reply):
            # noinspection PyProtectedMember
            data = details._asdict()
            for i in list(data.items()):
                key = i[0]
                value = i[1]
                if type(value) is str:
                    value = self._fix_string(value)
                    data[key] = value
            datalist.append(data)
        try:
            jd = json.dumps(datalist)
        except Exception:
            self.LOG.error(reply)
            raise
        self.LOG.debug('{}'.format(jd))
        return jd

    def _handle_mac(self, reply):
        """
        Handles the vhost sw interface dump reply

        :param reply: The api call reply
        :type reply: list
        """
        datalist = []
        for idx, details in enumerate(reply):
            # noinspection PyProtectedMember
            data = details._asdict()
            for i in list(data.items()):
                key = i[0]
                value = i[1]
                if type(value) is str:
                    if key == 'l2_address':
                        value = binascii.hexlify(value)
                        cnt = 0
                        val2 = ''
                        for i in value:
                            cnt = cnt + 1
                            if cnt > 12:
                                break
                            val2 += i
                            if cnt % 2 == 0 and cnt < 12:
                                val2 += ':'
                        value = val2
                    else:
                        value = self._fix_string(value)
                    data[key] = value
            datalist.append(data)
        try:
            jd = json.dumps(datalist, skipkeys=True)
        except Exception:
            self.LOG.error(reply)
            raise
        self.LOG.debug('{}'.format(jd))
        return jd

    @staticmethod
    def _get_vhost_status(vhost_data, socket_filename):
        """
        Handles the vhost sw interface dump reply

        :param vhost_data: The Vhost data, json
        :type vhost_data: str
        :param socket_filename: The filename of the socket we are looking at
        :returns 0 if the interface is good, -1 if it is not, the virtual
         interface data
        """

        # Get the virtual interface list
        vints = json.loads(vhost_data)

        # Get the interface associated with the socket
        vint = [x for x in vints if x['sock_filename'] == socket_filename]

        # Check and make sure an interface is associated with the socket
        if len(vint) == 0:
            return 1, ''

        # Check for a socket error
        if 'sock_errno' in vint[0]:
            if vint[0]['sock_errno'] != 0:
                return 2, ''
        else:
            return 3, ''

        # Check the memory regions
        if 'num_regions' in vint[0]:
            if vint[0]['num_regions'] == 0:
                return 4, ''
        else:
            return 5, ''

        return 0, vint[0]

    @staticmethod
    def _get_vhost_set(vhost_data):
        """
        Handles the vhost sw interface dump reply

        :param vhost_data: The Vhost data, json
        :type vhost_data: str
        :param socket_filename: The filename of the socket we are looking at
        :returns 0 if the interface is good, -1 if it is not, the virtual
         interface data
        """

        # Get the virtual interface list
        vints = json.loads(vhost_data)

        intf_set = set()
        for v in vints:
            intf_set.add(v['interface_name'])
        return intf_set

    @staticmethod
    def _get_vhost_mac_set(mac_data):
        """
        Handles the vhost sw interface dump reply

        :param mac_data: vhost sw interface dump dict
        :type mac_data: str
        :returns set of macs associated with the vhost sw interfaces
        """
        # Get the virtual interface list
        ints = json.loads(mac_data)

        # Get the interface associated with the socket
        virt_ints = [x for x in ints if 'Virtual' in x['interface_name']]
        mac_set = set()
        for virt_int in virt_ints:
            mac_set.add(virt_int['l2_address'])
        return mac_set

    def get_version(self):
        """
        Get's the version information.

        :returns The version information

        """
        with VppCtxt(self.client_name, self.LOG) as vppp:
            version = self._handle_reply(vppp.show_version())
        return json.loads(version)

    def vhost_status(self, socketname):
        """
        Get's the vhost status given the socket name of the vhost interface.

        :param socketname: The socket name of the virtual interface
        :type socketname: str
        :returns A tuple containing the status of the interface
         The first item is the tuple is the status 0 if the interface is good,
         -1 if it isn't
         The second item in the tuple is information about the interface

        """
        with VppCtxt(self.client_name, self.LOG) as vppp:
            vhs = self._handle_vhost(vppp.sw_interface_vhost_user_dump())
            status, vint = self._get_vhost_status(vhs, socketname)
        return status, vint

    def create_vhost_user_if(self, socketname, server, mac_address, tag):
        """
        Creates the vhost status given the socket name of the vhost interface.

        :param socketname: The socket name of the virtual interface
        :param server: 1/0 indicates vhost-user server/client side of the
        socket is being created
        :param mac_address: Custom mac-address to be assigned to the interface
        :param tag: An identifier for the port, usually neutron port UUID
        :returns None
        """
        vhu_reply = ''
        with VppCtxt(self.client_name, self.LOG) as vppp:
            vhu_reply = self._handle_reply(vppp.create_vhostuser_socket(
                socketname, server, mac_address, tag))
        return json.loads(vhu_reply)['sw_if_index']

    def show_vhost_user(self):
        """
        Get the set of all vhost user interfaces.

        :param None
        :returns Set of all vhost user interface names
        """
        with VppCtxt(self.client_name, self.LOG) as vppp:
            rep = self._handle_vhost(vppp.sw_interface_vhost_user_dump())
            vh_set = self._get_vhost_set(rep)
        return vh_set

    def show_vhost_sock(self):
        """
        Get the set of all vhost user interfaces.

        :param None
        :returns Set of all vhost user interface names
        """
        with VppCtxt(self.client_name, self.LOG) as vppp:
            rep = self._handle_vhost(vppp.sw_interface_vhost_user_dump())
            vh_set = self._get_vhost_sock_set(rep)
        return vh_set

    def get_vhost_macs(self):
        """
        Get the set of all vhost user interface mac addresses.

        :param None
        :returns Set of all vhost user interface mac addresses.
        """
        with VppCtxt(self.client_name, self.LOG) as vppp:
            rep = self._handle_mac(vppp.sw_interface_dump())
            vh_mac = self._get_vhost_mac_set(rep)
        return vh_mac

    def get_vhost_tag_dicts(self):
        """
        Get the set of all vhost user interface tag and access-interfaces.

        :param None
        :returns Set of all vhost user interface tag and access-interface
         tuples.
        """
        tag_dict = {}
        with VppCtxt(self.client_name, self.LOG) as vppp:
            rep = self._handle_mac(vppp.sw_interface_dump())
            interfaces = json.loads(rep)
            rep_vhost = self._handle_vhost(vppp.sw_interface_vhost_user_dump())
            vints = json.loads(rep_vhost)
            # Get the interface associated with the socket
            for interface in interfaces:
                if interface['interface_name'].startswith('Virtual'):
                    curr_int = interface['interface_name']
                    sock_name = ''
                    for vint in vints:
                        if vint['interface_name'] == curr_int:
                            sock_name = vint['sock_filename']
                            break
                    tag_dict.update({interface['tag']: sock_name})
                if interface['interface_name'].startswith('host-'):
                    tag_dict.update({interface['tag']:
                        interface['interface_name'][5:]})
        return tag_dict

    def vhost_name_from_mac(self, mac):
        """
        Get the vhost user interface socketfilename given the mac address.

        :param mac: mac address of the vhost user interface.
        :returns vhost user interface with the given mac address.
        """
        with VppCtxt(self.client_name, self.LOG) as vppp:
            rep = self._handle_mac(vppp.sw_interface_dump())
            # Get the virtual interface list
            ints = json.loads(rep)

            # Get the interface associated with the socket
            vints = [x for x in ints if 'Virtual' in x['interface_name']]
            port_name = ''
            for vint in vints:
                if vint['l2_address'] == mac:
                    port_name = vint['interface_name']
                    break
            rep = self._handle_vhost(vppp.sw_interface_vhost_user_dump())
            vints = json.loads(rep)
            sock_name = ''
            for v in vints:
                if v['interface_name'] == port_name:
                    sock_name = v['sock_filename']
                    break
        return sock_name

    def vhost_details_from_tag(self, tag):
        """
        Get the vhost user interface socketfilename, mac address given the tag.

        :param tag: tag on the vhost user interface.
        :returns vhost user interface, mac address and sw_if_index.
        """
        with VppCtxt(self.client_name, self.LOG) as vppp:
            rep = self._handle_mac(vppp.sw_interface_dump())
            # Get the virtual interface list
            interfaces = json.loads(rep)

            # Get the interface associated with the socket
            port_name = ''
            port_mac = ''
            sock_name = ''
            sw_if_index = -1
            for intf in interfaces:
                if intf['tag'] == tag:
                    port_name = intf['interface_name']
                    port_mac = intf['l2_address']
                    sw_if_index = intf['sw_if_index']
                    break
            if port_name:
                if port_name.startswith('Virtual'):
                    rep = self._handle_vhost(
                        vppp.sw_interface_vhost_user_dump())
                    vints = json.loads(rep)
                    for v in vints:
                        if v['interface_name'] == port_name:
                            sock_name = v['sock_filename']
                            break
                elif port_name.startswith('host-'):
                    sock_name = port_name[5:]
                else:
                    sock_name = port_name
        return sock_name, port_mac, sw_if_index

    def delete_vhost_user_if(self, sock_name):
        """
        Delete the vhost user interface using the socketfilename.

        :param sock_name: vhost-user socketfilename
        :returns None
        """
        with VppCtxt(self.client_name, self.LOG) as vppp:
            rep = self._handle_vhost(vppp.sw_interface_vhost_user_dump())
            # Get the virtual interface list
            vints = json.loads(rep)

            if_index = -1
            for v in vints:
                if sock_name in v['sock_filename']:
                    if_index = v['sw_if_index']
                    break
            if if_index != -1:
                self._handle_reply(vppp.delete_vhostuser_socket(if_index))

    def set_interface_state(self, sw_if_index, state):
        """
        Set the interface state using the sw_if_index.

        :param sw_if_index: if-index of the interface
        :param state: admin up/down state(1/0)
        :returns None
        """
        with VppCtxt(self.client_name, self.LOG) as vppp:
            self._handle_reply(vppp.set_interface_state(sw_if_index, state))

    def create_host_interface(self, lnx_veth_name, mac_address, uuid):
        """
        Create the host interface using the linux side veth name.

        :param uuid: uuid of the neutron port
        :param lnx_veth_name: name of the veth linux interface
        :returns sw_if_index: if_index of the created interface
        """
        with VppCtxt(self.client_name, self.LOG) as vppp:
            rep = self._handle_reply(vppp.af_packet_create(lnx_veth_name,
                                        mac_address))
            sw_if_index = json.loads(rep)['sw_if_index']
            self._handle_reply(vppp.set_interface_tag(sw_if_index, uuid))
        return sw_if_index

    def delete_host_interface(self, lnx_veth_name):
        """
        Delete the host interface using the linux side veth name.

        :param lnx_veth_name: name of the veth linux interface
        :returns None
        """
        with VppCtxt(self.client_name, self.LOG) as vppp:
            self._handle_reply(vppp.af_packet_delete(lnx_veth_name))

    def set_interface_mtu(self, sw_if_index, mtu):
        """
        Set mtu using the sw_if_index of the interface.

        :param sw_if_index: if-index of the interface
        :param mtu: mtu
        :returns None
        """
        with VppCtxt(self.client_name, self.LOG) as vppp:
            self._handle_reply(vppp.set_interface_mtu(sw_if_index, mtu))
