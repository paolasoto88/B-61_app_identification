# TODO: tor was removed from APP_IDENTIFICATION_LABELS must be added when classifying
APP_IDENTIFICATION_LABELS = ['aim', 'email', 'facebook', 'ftps', 'gmail', 'hangout', 'icq', 'netflix', 'scp',
                             'sftp', 'skype', 'spotify', 'torrent', 'voipbuster', 'vimeo', 'youtube']
TOR_TRAFFIC_LABELS = ['google', 'facebook', 'youtube', 'twitter', 'vimeo']
TRAFFIC_CLASES_LABELS = ['chat', 'file', 'email', 'video', 'torrent', 'audio']
TRAFFIC_CLASES = {'chat': ['icq', 'aim', 'skype', 'facebook', 'hangout', 'gmail'], 'email': ['smtps', 'pop', 'imaps'],
                   'file': ['skype', 'ftps', 'sftp', 'scp'],
                   'video': ['vimeo', 'youtube', 'facebook', 'skype', 'hangouts', 'netflix'],
                   'torrent': ['bittorrent', 'torrent', 'utorrent'], 'audio': ['facebook', 'skype', 'hangout',
                                                                               'spotify', 'voipbuster']}
