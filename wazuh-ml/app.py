from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def receive_alert():
    # Get the data sent by the project
    data = request.json
    
    if data:
        print(f"Alert Received: {data}")
        # Add your logic here (e.g., send an email, log to a file)
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"status": "bad request"}), 400

if __name__ == '__main__':
    # Runs on http://localhost:5000/webhook
    app.run(port=5000)