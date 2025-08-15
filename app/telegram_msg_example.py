#!/usr/bin/python3
import sqlite3
from hexdump import hexdump # simple-hexdump
conn = sqlite3.connect('cache4.db')
cursor = conn.cursor()

# Chatroom UID
#chatroom_title = 'the hacker news'
#cursor.execute('''SELECT uid FROM chats WHERE name = ?''', (chatroom_title,))
#uid = cursor.fetchone()[0]

# Show messages
#cursor.execute('''SELECT data FROM messages_v2 WHERE uid = ?''', (-uid,))
cursor.execute('''SELECT data FROM messages_v2''')
for data in cursor.fetchall():
    print(hexdump(data[0]))
