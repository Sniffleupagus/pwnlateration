# PWNlateration
Locate wifi endpoints using RSSI data from multiple pwnagotchis

Trilateration is a way to determine the location of a point by measuring the distance from it to at least 3 known points. It is how GPS determines its location relative to the satellites it can see.

PWNlateration is an attempt to locate wifi endpoints using data collected from multiple nearby pwnagotchies, using RSSI as a proxy for distance. Data is shared using the pwngrid mesh advertisement. A pwny can add the mac address of the endpoint to a "request" list. Every peer that sees the request collects RSSI data from bettercap, and inserts data for any requested endpoints into its advertisement. The interested pwny collects the data from its peers and can use that to estimate its location.

Right now pwnlaterate.py script will report which pwny is closest to each endpoint, and show the RSSI from each pwny to the target.

## Usage
PWNlaterate is not a pwnagotchi plugin. pwnlaterate.py is intended to eventually be run as a system service, but not yet. All output is displayed on stdout, so you need to have a terminal open to see it. For now, run it from the command line on any pwny you wish to include. Running it in a screen session will let it keep running in the background when you disconnect the pwny network access.
```
pwnlaterate -d [-p PASSWORD]  # run as a daemon. Use PASSWORD for encryption instead of "triangle"
pwnlaterate -w MAC_ADDRESS    # watch MAC_ADDRESS (add it to the requests list)
pwnlaterate -u MAC_ADDRESS    # unwatch MAC_ADDRESS (remove from requests)
```
## Sample output
```
[2025-01-10 20:29:18,861] [INFO] (pwnlaterate.py:205) daemon: -------
[2025-01-10 20:29:23,900] [INFO] (pwnlaterate.py:113) update_advertisement: Looking for: dict_keys(['84:20:aa:bb:cc:dd'])
[2025-01-10 20:29:24,041] [INFO] (pwnlaterate.py:185) process_locations: 'Mambo_number9' 84:20:aa:bb:cc:dd (SHENZHEN RF-LINK TECHNOLOGY CO.,LTD.)
[2025-01-10 20:29:24,041] [INFO] (pwnlaterate.py:189) process_locations: 	{'rssi': -102, 'last_seen': '2025-01-10T20:28:26.470301079Z', 'peer': 'pocketBanana', 'peer_id': 'BLAHBLAHBLAH', 'peer_rssi': -75}
[2025-01-10 20:29:24,042] [INFO] (pwnlaterate.py:189) process_locations: 	{'rssi': -50, 'last_seen': '2025-01-10T20:29:23.862448872Z', 'peer': 'bananagotchi', 'peer_id': 'ANDSOFORTH', 'peer_rssi': 0}
[2025-01-10 20:29:24,042] [INFO] (pwnlaterate.py:195) process_locations: CLOSEST: 84:20:aaa:bb:cc:dd is closest to bananagotchi, pocketBanana: -102/-75, bananagotchi: -50/0
[2025-01-10 20:29:24,043] [INFO] (pwnlaterate.py:205) daemon: -------
```
