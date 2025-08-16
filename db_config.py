import mysql.connector
from mysql.connector import Error

def get_connection():
    
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",  # your MySQL password
            database="newFyp_db"
        )
        if not conn:
            raise Error("Connection object not connected")
        if not conn.is_connected():
            raise Error("Connection object not connected")
        return conn, conn.cursor()
    except Error as e:
        print("MySQL connection failed:", e)
        return None, None
