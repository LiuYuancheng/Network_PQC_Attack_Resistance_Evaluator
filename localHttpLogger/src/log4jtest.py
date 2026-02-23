import logging
import logging.handlers
import requests

# 1. Setup Logger
logger = logging.getLogger('HttpsLogger')
logger.setLevel(logging.INFO)

# 2. Configure HTTPHandler for HTTPS (Secure)
# Note: In production, ensure valid SSL certificates
secure_handler = logging.handlers.HTTPHandler(
    host='y.arin.net',
    url='/log-endpoint',
    method='POST',
    secure=True # Enables HTTPS
)
logger.addHandler(secure_handler)

# 3. Log a message (this triggers the HTTPS request)
logger.info('This is a secure log message sent via HTTPS POST.')

print("Log sent.")
