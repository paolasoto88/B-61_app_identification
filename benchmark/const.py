# TODO: tor was removed from APP_IDENTIFICATION_LABELS must be added when classifying
APP_IDENTIFICATION_LABELS = ['aim', 'email', 'facebook', 'ftps', 'gmail', 'hangout', 'icq', 'netflix', 'scp',
                             'sftp', 'skype', 'spotify', 'torrent', 'voipbuster', 'vimeo', 'youtube']
TOR_TRAFFIC_LABELS = ['google', 'facebook', 'youtube', 'twitter', 'vimeo']
TRAFFIC_CLASES_LABELS = ['chat', 'file', 'email', 'video', 'torrent', 'audio']
TRAFFIC_CLASES = {'chat': ['icq', 'aim', 'skype', 'facebook', 'hangout', 'gmail'], 'email': ['smtps', 'pop', 'imaps'],
                   'file': ['skype', 'ftps', 'sftp', 'scp'],
                   'video': ['vimeo', 'youtube', 'facebook', 'skype', 'hangouts', 'netflix', 'spotify'],
                   'torrent': ['bittorrent', 'torrent', 'utorrent'], 'audio': ['facebook', 'skype', 'hangout', 'voipbuster']}
ETHERNET_TYPES = {187:'dpkt.edp.EDP', 2048: 'dpkt.ip.IP', 2054: 'dpkt.arp.ARP', 34978: 'dpkt.aoe.AOE',
                  8192: 'dpkt.cdp.CDP', 8196:'dpkt.dtp.DTP', 33079:'dpkt.ipx.IPX', 34525: 'dpkt.ip6.IP6',
                  34827: 'dpkt.ppp.PPP', 34916: 'dpkt.pppoe.PPPoE', 25944: 'dpkt.ethernet.Ethernet'}
