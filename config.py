import os
from dotenv import load_dotenv

load_dotenv()

PROVIDER_URL = os.getenv("PROVIDER_URL")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
