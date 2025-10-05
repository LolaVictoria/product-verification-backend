# app/monitoring/metrics.py
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from flask import Response, Flask, request
import time
import functools

app = Flask(__name__)
# Metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration')
ACTIVE_CONNECTIONS = Gauge('active_database_connections', 'Active database connections')

def track_requests(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        REQUEST_COUNT.labels(method=request.method, endpoint=request.endpoint).inc()
        
        with REQUEST_DURATION.time():
            return f(*args, **kwargs)
    return wrapper

@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype='text/plain')