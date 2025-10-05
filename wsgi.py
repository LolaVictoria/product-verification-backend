"""
WSGI Entry Point for Production Deployment
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app as app_module

# Create application instance
app = app_module.create_app()

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)