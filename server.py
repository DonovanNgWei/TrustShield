from flask import Flask, request, jsonify
from db_config import get_connection

app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({"message": "Secure File Sharing API is running."})

@app.route('/test-db')
def test_db():
    conn, cursor = get_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({"status": "connected", "tables": tables})
    else:
        return jsonify({"status": "error", "message": "Failed to connect to DB"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)