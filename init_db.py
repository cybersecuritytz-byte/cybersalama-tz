import sqlite3

conn = sqlite3.connect('cyber_salama.db')
cursor = conn.cursor()

cursor.execute("CREATE TABLE IF NOT EXISTS threat_keywords (id INTEGER PRIMARY KEY, keyword TEXT UNIQUE, risk_level TEXT, category TEXT)")
cursor.execute("CREATE TABLE IF NOT EXISTS traffic_logs (id INTEGER PRIMARY KEY, sender TEXT, recipient TEXT, message_text TEXT, risk_level TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")

seed_keywords = [
    ('pin', 'HIGH', 'Credential Theft'),
    ('otp', 'HIGH', 'Credential Theft'),
    ('password', 'HIGH', 'Credential Theft'),
    ('namba ya siri', 'HIGH', 'Credential Theft'),
    ('umeshinda', 'MEDIUM', 'Bait Hook'),
    ('zawadi', 'MEDIUM', 'Bait Hook'),
    ('bonyeza link', 'MEDIUM', 'Phishing URL'),
    ('imezuiwa', 'MEDIUM', 'Urgency Request')
]
cursor.executemany("INSERT OR IGNORE INTO threat_keywords (keyword, risk_level, category) VALUES (?, ?, ?)", seed_keywords)

conn.commit()
conn.close()
print("[+] Hongera! Database imetengenezwa vizuri.")