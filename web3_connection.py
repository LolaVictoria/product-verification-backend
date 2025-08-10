# web3_connection.py
import os
from dotenv import load_dotenv
from web3 import Web3

# Load environment variables
load_dotenv()

PRIVATE_KEY = os.getenv("PRIVATE_KEY")
PROVIDER_URL = os.getenv("PROVIDER_URL")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")

# Connect to blockchain
w3 = Web3(Web3.HTTPProvider(PROVIDER_URL))

if not w3.is_connected():
    raise ConnectionError("Failed to connect to the Ethereum network")

# Load contract ABI from file
with open("contract/contract_abi.json", "r") as abi_file:
    contract_abi = abi_file.read()

# Create contract instance
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)

# Create account object from private key
account = w3.eth.account.from_key(PRIVATE_KEY)
