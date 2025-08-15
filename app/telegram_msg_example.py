#!/usr/bin/python3
import sqlite3
import string
from hexdump import hexdump # simple-hexdump
conn = sqlite3.connect('cache4.db')
cursor = conn.cursor()

BGREEN= '\033[92m'
NOCOLOR = '\033[0m'

# Chatroom UID
#chatroom_title = 'the hacker news'
#cursor.execute('''SELECT uid FROM chats WHERE name = ?''', (chatroom_title,))
#uid = cursor.fetchone()[0]

# Show messages
#cursor.execute('''SELECT data FROM messages_v2 WHERE uid = ?''', (-uid,))
cursor.execute('''SELECT data FROM messages_v2''')
for data in cursor.fetchall():
    print(hexdump(data[0]))
    msg = ''.join([chr(c) for c in data[0][44:] if chr(c) in string.printable])
    print(f"Extracted message : {BGREEN} {msg} {NOCOLOR}")
