from web3 import Web3
import json
from config import PROVIDER_URL, CONTRACT_ADDRESS

# Connect to Sepolia via Infura/Alchemy
w3 = Web3(Web3.HTTPProvider(PROVIDER_URL))

# Load contract ABI
with open("ProductRegistry.json") as f:
    contract_abi = json.load(f)

# Create contract instance
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)
