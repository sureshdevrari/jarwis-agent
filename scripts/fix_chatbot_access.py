"""Fix chatbot access for individual, professional, and enterprise users"""
import sqlite3

conn = sqlite3.connect('data/jarwis.db')
cursor = conn.cursor()

# Update individual, professional, and enterprise users to have chatbot access
cursor.execute("""UPDATE users SET has_chatbot_access = 1 WHERE plan IN ('individual', 'professional', 'enterprise')""")
print(f'Updated {cursor.rowcount} users')
conn.commit()

# Show updated users
cursor.execute('SELECT email, plan, has_chatbot_access FROM users')
for row in cursor.fetchall():
    print(f'  {row[0]}: plan={row[1]}, chatbot_access={row[2]}')

conn.close()
print("Done!")
