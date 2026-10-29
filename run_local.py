import socket, threading, time, urllib.request, webbrowser
from app import app
HOST, PORT = '127.0.0.1', 8766
URL = f'http://{HOST}:{PORT}/'

def open_when_ready():
    for _ in range(60):
        try:
            with urllib.request.urlopen(URL + 'api/health', timeout=1) as response:
                if response.status == 200:
                    webbrowser.open(URL)
                    return
        except Exception:
            time.sleep(0.25)

if __name__ == '__main__':
    with socket.socket() as probe:
        try:
            probe.bind((HOST, PORT))
        except OSError:
            raise SystemExit(f'Port {PORT} is already in use. Close the other local service and retry.')
    print(f'EventSage Local: {URL}\nLogs are processed on this PC. Keep this window open; Ctrl+C stops the service.')
    threading.Thread(target=open_when_ready, daemon=True).start()
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False, threaded=True)
