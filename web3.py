from web3 import Web3
import json
import os
from dotenv import load_dotenv

load_dotenv()

infura_url = os.getenv("PROVIDER_URL")
web3 = Web3(Web3.HTTPProvider(infura_url))

with open("contract_abi.json") as f:
    abi = json.load(f)

contract_address = web3.to_checksum_address(os.getenv("CONTRACT_ADDRESS"))
contract = web3.eth.contract(address=contract_address, abi=abi)
