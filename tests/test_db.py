import sqlite3

def create_connection(db_file):

    conn = None

    try:
        conn = sqlite3.connect(db_file)
    except Exception as e:
        print(e)

    return conn

def select_all(conn):

    cur = conn.cursor()
    #cur.execute("INSERT INTO user (username, password) VALUES ('lcy', '123456')")
    cur.execute("SELECT * FROM user")
    rows = cur.fetchall()

    for row in rows:
        print(row)

if __name__ == "__main__":
    conn = create_connection("../instance/flaskr.sqlite")
    select_all(conn)
