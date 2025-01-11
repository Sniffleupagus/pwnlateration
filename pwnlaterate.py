#!/usr/bin/env python3
#
# pwnangulate.py
#
# triangulate location of WIFI devices using multiple pwnagotchis
# sharing RSSI information over pwngrid mesh
#
import getopt, sys
import time
import json
import hashlib
import base64
import logging
import logging.handlers
from cryptography.fernet import Fernet

from pwnagotchi.bettercap import Client as bettercap

from pwnagotchi import grid as pwngrid

formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] (%(filename)s:%(lineno)d) %(funcName)s: %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

class Pwnangulator:
    password = None
    watchlist = {}
    bc = None

    def __init__(self, password, bcport=8081, bcusername='pwnagotchi', bcpassword='pwnagotchi', watchlist={}):
        self.bc = bettercap('localhost', port=bcport, username=bcusername, password=bcpassword)
        self.password = password
        self.watchlist = watchlist
    
    def generate_key(self):
        """Generate a Fernet key from a password"""
        if self.password:
            ekey = hashlib.sha256(self.password.encode()).digest()
            return base64.urlsafe_b64encode(ekey)
        else:
            return None
    
    def encrypt_data(self, obj):
        """Encrypts a message with a password."""
        f = Fernet(self.generate_key())
        data = json.dumps(obj)
        encrypted_message = f.encrypt(data.encode()).decode()
        logging.debug("Encrypted to %s" % encrypted_message)
        return encrypted_message

    def decrypt_data(self, encrypted_message, default=None):
        """Decrypts a message with a password."""
        if encrypted_message:
            f = Fernet(self.generate_key())
            decrypted_message = f.decrypt(encrypted_message.encode()).decode()
            try:
                return json.loads(decrypted_message)
            except Exception as e:
                return decrupted_message
        else:
            return default

    def watch(self, mac):
        """add mac address to the requests list in advertisement"""
        my_data = pwngrid.get_advertisement_data()
        watcher = my_data.get('identity')
        pwnang = self.decrypt_data(my_data.get('pwnangulate'))
        if not pwnang: pwnang = {}
        if 'req' not in pwnang:
            pwnang['req'] = [mac]
        elif mac not in pwnang['req']:
            pwnang['req'].append(mac)
        pwngrid.set_advertisement_data({'pwnangulate':self.encrypt_data(pwnang)})

    def unwatch(self, mac):
        """remove mac address from the requests list in advertisement"""
        my_data = pwngrid.get_advertisement_data()
        watcher = my_data.get('identity')
        pwnang = self.decrypt_data(my_data.get('pwnangulate'))
        if pwnang:
            if 'req' in pwnang:
                if mac in pwnang['req']:
                    pwnang['req'].remove(mac)
                if len(pwnang['req']) == 0:
                    del pwnang['req']
            pwngrid.set_advertisement_data({'pwnangulate':self.encrypt_data(pwnang)})

    def listVisibleMacs(self):
        def devInfo(device, indent=""):
            host = device.get('hostname', '-')
            if host == '':
                host = '-'
            vendor = device.get('vendor', "-")
            if vendor == '':
                vendor = '-'
            return "%s%4d\t%-20s\t%-30s\t%s\t%s" % (indent,
                                                   device.get('rssi', -420),
                                                   host[:19], vendor[:29],
                                                   device.get('mac', '--:--:--:--:--:--'),
                                                   device.get('last_seen', "--"))

        for ap in self.bc.session("session/wifi").get('aps', []):
            print("%s" % devInfo(ap, "AP "))
            for cl in ap.get('clients', []):
                print(devInfo(cl, "cl "))

    def updateWatchlist(self, advdata):
        """collect watchlists from peers"""
        name = advdata.get('identity')
        pwnang = self.decrypt_data(advdata.get('pwnangulate'))
        
        if not pwnang:
            return
        
        # add this peer's requests to watchlist
        for mac in pwnang.get('req', []):
            if mac not in self.watchlist.keys():
                # add new item with this peer as interested
                self.watchlist[mac] = [name]
            elif name not in self.watchlist[mac]:
                # add this peer to this item
                self.watchlist[mac].append(name)

        for mac in self.watchlist.keys():
            if name in self.watchlist[mac] and mac not in pwnang.get('req', []):
                self.watchlist[mac].remove(name)    # remove peer from watchlist if not interested
                if len(self.watchlist[mac]) == 0:
                    del self.watchlist[mac]         # remove mac from watchlist if no one watching

    def update_advertisement(self):
        """gather AP info and update shared information in advertisements"""
        macs = self.watchlist.keys()
        if len(macs):
            logging.info("Looking for: %s" % macs)
        rssi_stats = {}
        if len(macs):
            wifi_data = self.bc.session("session/wifi")
            for ap in wifi_data['aps']:
                if ap['mac'] in macs:
                    logging.debug("* AP %s (%s) %s \t\tFOUND" % (ap.get('hostname', "--"), ap.get('channel', -1), ap['mac']))
                    rssi_stats[ap['mac']] = {'rssi': ap['rssi'], 'last_seen': ap['last_seen']}
                else:
                    logging.debug("| AP %s (%s) %s (%s)" % (ap.get('hostname', "--"), ap.get('channel', -1), ap['mac'], ap.get('rssi', '--')))
                    pass
                for cl in ap.get('clients', []):
                    if cl['mac'] in macs:
                        logging.debug ("*** CL %s %s '%s' \t\tFOUND" % (cl.get('mac'), cl.get('vendor'), cl.get('hostname', '--')))
                        rssi_stats[cl['mac']] = {'rssi': cl['rssi'],
                                                 'last_seen': cl['last_seen'],
                                                 }
                    else:
                        logging.debug("+-> CL %s %s '%s' (%s)" % (cl.get('mac'), cl.get('vendor'), cl.get('hostname', '--'), cl.get('rssi', '--')))
                        pass

        my_data = pwngrid.get_advertisement_data()
        pwnang = self.decrypt_data(my_data.get('pwnangulate'), {})
        if len(rssi_stats.keys()):
            pwnang['rssi'] = rssi_stats
            pwngrid.set_advertisement_data({'pwnangulate': self.encrypt_data(pwnang)})
        elif pwnang and 'rssi' in pwnang:
            del pwnang['rssi']
            pwngrid.set_advertisement_data({'pwnangulate': self.encrypt_data(pwnang)})

    def process_locations(self):
        peers = pwngrid.peers()
        my_data = pwngrid.get_advertisement_data()
        my_pwnang = self.decrypt_data(my_data.get('pwnangulate'))
        peers.append( {'advertisement':my_data, 'rssi':0})

        interps = {}
        logging.debug("PWNangulating:")
        for p in peers:
            logging.debug("Peer: %s sees" % p.get('advertisement', {}).get('name', "--"))
            adv = p.get('advertisement', {})
            peer_rssi = self.decrypt_data(adv.get('pwnangulate'), {}).get('rssi', {})
            for mac in peer_rssi.keys():
                peer_rssi[mac]['peer'] = adv.get('name', "<unknown>")
                peer_rssi[mac]['peer_id'] = adv.get('identity', "<unknown>")
                peer_rssi[mac]['peer_rssi'] = p.get('rssi', -420)   # signal strength "me" to peer. 'rssi' is peer to target
                logging.debug("\t%s %s" % (mac, peer_rssi[mac]))
                if mac not in interps:
                    interps[mac] = []
                interps[mac].append(peer_rssi[mac])

        wifi_data = self.bc.session("session/wifi").get('aps', [])

        my_aps = {}
        my_macs = interps.keys()
        for ap in wifi_data:
            if ap.get('mac', None) in my_macs:
                logging.debug("Found %s" % ap.get('mac'))
                my_aps[ap.get('mac')] = ap

            for cl in ap.get('clients', []):
                if cl['mac'] in my_macs:
                    logging.debug("Found %s" % cl.get('mac'))
                    my_aps[cl.get('mac')] = cl

        for mac in my_pwnang.get('req', []):   #interps.keys():
            if mac not in interps:
                continue
            closest = None
            data = interps[mac]
            dists = []
            if mac in my_aps:
                logging.info("'%s' ch %s  %s (%s)" % (my_aps[mac]['hostname'], my_aps[mac]['channel'], mac, my_aps[mac]['vendor']))
            else:
                logging.error("I DO NOT KNOW %s" % mac)
            for peer in data:
                logging.info("\t%s" % peer)
                if not closest or peer['rssi'] > closest['rssi']:
                    closest = peer
                dists.append("%s: %d/%d" % (peer['peer'], peer['rssi'], peer['peer_rssi']))

            if closest:
                logging.info("CLOSEST: %s is closest to %s, %s" % (mac, closest['peer'], ', '.join(dists)))

    def daemon(self):
        """run pwnangulate daemon"""
        keepGoing = True
        logging.info("Main loop starting")
        while keepGoing:
            self.main()
            time.sleep(5)
        
    
    def main(self):
        #wifi_data = self.bc.session("session/wifi")
        #print(wifi_data)
        peers = pwngrid.peers()
        self.watchlist = {}
        for p in peers:
            adv = p['advertisement']
            logging.debug("Peer: %s" % (adv['name']))
            if 'pwnangulate' in adv:
                pwnang = self.decrypt_data(adv.get('pwnangulate'))
                self.updateWatchlist(adv)
        
        my_data = pwngrid.get_advertisement_data()
        self.updateWatchlist(my_data)

        self.update_advertisement()
        my_data = pwngrid.get_advertisement_data()

        if 'pwnangulate' in my_data:
            logging.debug("Me: %s" % self.decrypt_data(my_data['pwnangulate']))

            self.process_locations()

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "odlsw:u:p:", ["once", "daemon", "list", "syslog", "watch='MAC'", "unwatch='MAC'", "password='encryption password'"])
    except getopt.GetoptError as err:
        logging.exception(err)
        sys.exit(2)

    watchlist = []
    unwatchlist = []
    daemon = False
    once = False
    password = "triangle"
    
    p = Pwnangulator(password)

    for o, a in opts:
        if o in ('-d', '--daemon'):
            syslog_handler = logging.handlers.SysLogHandler(address=('localhost', 514))
            logger.addHandler(syslog_handler)
            #logger.removeHandler(console_handler)
            daemon = True
        if o in ('-o', '--once'):
            once = True
        elif o in ('-l', '--list'):
            p.listVisibleMacs()
        elif o in ('-s', '--syslog'):
            syslog_handler = logging.handlers.SysLogHandler(address=('localhost', 514))
            logger.addHandler(syslog_handler)
        elif o in ('-w', '--watch'):
            watchlist.append(a)
        elif o in ('-u', '--unwatch'):
            unwatchlist.append(a)
        elif o in ('-p', '--password'):
            password = a
            p.password = a

    for mac in watchlist:
        p.watch(mac)
    
    for mac in unwatchlist:
        p.unwatch(mac)
    
    if once:
        p.main()
    elif daemon:
        p.daemon()

