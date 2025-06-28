import subprocess
import json
import os
import time
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_structured_data

# Configuration
RPC_URL = "http://localhost:8545"  # Assuming local Anvil/Hardhat node
PRIVATE_KEY = os.environ.get("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")  # Default Anvil private key
USDC_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"  # This will need to be replaced with your actual USDC contract address

# Initialize Web3
w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = Account.from_key(PRIVATE_KEY)
address = account.address

print(f"Using account: {address}")

# --- Arbiter executes (admin setup/testing) ---
def run_forge_build():
    """Build the contract using Forge."""
    print("Building contracts with Forge...")
    result = subprocess.run(
        ["forge", "build", "--optimize"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"Error building contracts: {result.stderr}")
        exit(1)
    
    print("Contracts built successfully!")
    return result.stdout

# --- Arbiter executes (contract deployment) ---
def deploy_contract():
    """Deploy the RefundProtocol contract."""
    print("Deploying RefundProtocol contract...")
    
    # Load the compiled contract
    with open("out/RefundProtocol.sol/RefundProtocol.json", "r") as f:
        contract_json = json.load(f)
    
    abi = contract_json["abi"]
    bytecode = contract_json["bytecode"]["object"]
    
    # Initialize contract
    RefundProtocol = w3.eth.contract(abi=abi, bytecode=bytecode)
    
    # Build construction transaction
    construct_txn = RefundProtocol.constructor(
        address,  # Using our address as the arbiter for testing
        USDC_ADDRESS,
        "RefundProtocol",
        "1"
    ).build_transaction({
        'from': address,
        'nonce': w3.eth.get_transaction_count(address),
        'gas': 3000000,
        'gasPrice': w3.eth.gas_price
    })
    
    # Sign and send transaction
    signed_txn = w3.eth.account.sign_transaction(construct_txn, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    contract_address = tx_receipt.contractAddress
    print(f"Contract deployed at: {contract_address}")
    
    # Initialize contract instance
    contract = w3.eth.contract(address=contract_address, abi=abi)
    return contract

# --- Customer executes (approve token spend by contract) ---
def approve_usdc(usdc_contract, spender, amount):
    """Approve the contract to spend USDC."""
    print(f"Approving {amount} USDC for {spender}...")
    
    approve_txn = usdc_contract.functions.approve(
        spender,
        amount
    ).build_transaction({
        'from': address,
        'nonce': w3.eth.get_transaction_count(address),
        'gas': 100000,
        'gasPrice': w3.eth.gas_price
    })
    
    signed_txn = w3.eth.account.sign_transaction(approve_txn, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    
    print("USDC approved successfully!")

# --- Customer executes ---
def make_payment(refund_contract, recipient, amount, refund_to):
    """Make a payment using the RefundProtocol."""
    print(f"Making payment of {amount} to {recipient}...")
    
    payment_txn = refund_contract.functions.pay(
        recipient,
        amount,
        refund_to
    ).build_transaction({
        'from': address,
        'nonce': w3.eth.get_transaction_count(address),
        'gas': 300000,
        'gasPrice': w3.eth.gas_price
    })
    
    signed_txn = w3.eth.account.sign_transaction(payment_txn, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    # Get payment ID from event logs
    payment_id = None
    for log in refund_contract.events.PaymentCreated().process_receipt(receipt):
        payment_id = log['args']['paymentID']
    
    print(f"Payment created with ID: {payment_id}")
    return payment_id

# --- Arbiter executes ---
def set_lockup_seconds(refund_contract, recipient, seconds):
    """Set lockup seconds for a recipient."""
    print(f"Setting lockup period of {seconds} seconds for {recipient}...")
    
    lockup_txn = refund_contract.functions.setLockupSeconds(
        recipient,
        seconds
    ).build_transaction({
        'from': address,
        'nonce': w3.eth.get_transaction_count(address),
        'gas': 100000,
        'gasPrice': w3.eth.gas_price
    })
    
    signed_txn = w3.eth.account.sign_transaction(lockup_txn, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    
    print("Lockup period set successfully!")

# --- Merchant executes ---
def withdraw_funds(refund_contract, recipient_key, payment_ids):
    """Withdraw funds after the lockup period."""
    recipient_account = Account.from_key(recipient_key)
    recipient_address = recipient_account.address
    
    print(f"Withdrawing funds for payment IDs {payment_ids}...")
    
    withdraw_txn = refund_contract.functions.withdraw(
        payment_ids
    ).build_transaction({
        'from': recipient_address,
        'nonce': w3.eth.get_transaction_count(recipient_address),
        'gas': 300000,
        'gasPrice': w3.eth.gas_price
    })
    
    signed_txn = w3.eth.account.sign_transaction(withdraw_txn, private_key=recipient_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    
    print("Funds withdrawn successfully!")

def sign_early_withdrawal(refund_contract, recipient_key, payment_ids, withdrawal_amounts, fee_amount, expiry):
    """Sign an early withdrawal request."""
    recipient_account = Account.from_key(recipient_key)
    recipient_address = recipient_account.address
    
    salt = int(time.time())
    
    # Get the hash of the early withdrawal info
    withdrawal_hash = refund_contract.functions.hashEarlyWithdrawalInfo(
        payment_ids,
        withdrawal_amounts,
        fee_amount,
        expiry,
        salt
    ).call()
    
    # Create the structured data for EIP-712 signing
    domain_separator = refund_contract.functions.DOMAIN_SEPARATOR().call()
    chain_id = w3.eth.chain_id
    
    # Sign the hash
    signed_message = Account.sign_message(
        encode_structured_data({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "EarlyWithdrawalByArbiter": [
                    {"name": "paymentIDs", "type": "uint256[]"},
                    {"name": "withdrawalAmounts", "type": "uint256[]"},
                    {"name": "feeAmount", "type": "uint256"},
                    {"name": "expiry", "type": "uint256"},
                    {"name": "salt", "type": "uint256"}
                ]
            },
            "primaryType": "EarlyWithdrawalByArbiter",
            "domain": {
                "name": "RefundProtocol",
                "version": "1",
                "chainId": chain_id,
                "verifyingContract": refund_contract.address
            },
            "message": {
                "paymentIDs": payment_ids,
                "withdrawalAmounts": withdrawal_amounts,
                "feeAmount": fee_amount,
                "expiry": expiry,
                "salt": salt
            }
        }),
        recipient_key
    )
    
    print(f"Early withdrawal signed by recipient: {recipient_address}")
    return salt, signed_message.v, signed_message.r, signed_message.s

def execute_early_withdrawal(refund_contract, payment_ids, withdrawal_amounts, fee_amount, expiry, salt, recipient, v, r, s):
    """Execute an early withdrawal as the arbiter."""
    print(f"Executing early withdrawal for {recipient}...")
    
    early_withdraw_txn = refund_contract.functions.earlyWithdrawByArbiter(
        payment_ids,
        withdrawal_amounts,
        fee_amount,
        expiry,
        salt,
        recipient,
        v,
        r,
        s
    ).build_transaction({
        'from': address,
        'nonce': w3.eth.get_transaction_count(address),
        'gas': 300000,
        'gasPrice': w3.eth.gas_price
    })
    
    signed_txn = w3.eth.account.sign_transaction(early_withdraw_txn, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    
    print("Early withdrawal executed successfully!")

def refund_by_arbiter(refund_contract, payment_id):
    """Execute a refund by the arbiter."""
    print(f"Executing refund for payment ID {payment_id}...")
    
    refund_txn = refund_contract.functions.refundByArbiter(
        payment_id
    ).build_transaction({
        'from': address,
        'nonce': w3.eth.get_transaction_count(address),
        'gas': 300000,
        'gasPrice': w3.eth.gas_price
    })
    
    signed_txn = w3.eth.account.sign_transaction(refund_txn, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    
    print("Refund executed successfully!")

def deposit_arbiter_funds(refund_contract, amount):
    """Deposit funds to the arbiter's balance."""
    print(f"Depositing {amount} to arbiter balance...")
    
    deposit_txn = refund_contract.functions.depositArbiterFunds(
        amount
    ).build_transaction({
        'from': address,
        'nonce': w3.eth.get_transaction_count(address),
        'gas': 200000,
        'gasPrice': w3.eth.gas_price
    })
    
    signed_txn = w3.eth.account.sign_transaction(deposit_txn, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    
    print("Funds deposited successfully!")

def main():
    # Create a test recipient account
    recipient_key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"  # Another default Anvil private key
    recipient_address = Account.from_key(recipient_key).address
    
    # Step 1: Build the contract
    run_forge_build()
    
    # Step 2: Deploy the contract
    refund_contract = deploy_contract()
    
    # Load USDC contract
    with open("path/to/USDC.json", "r") as f:  # You would need a proper USDC ABI
        usdc_abi = json.load(f)["abi"]
    
    usdc_contract = w3.eth.contract(address=USDC_ADDRESS, abi=usdc_abi)
    
    # Step 3: Set lockup period for the recipient
    set_lockup_seconds(refund_contract, recipient_address, 86400)  # 1 day
    
    # Step 4: Approve USDC for the contract
    approve_usdc(usdc_contract, refund_contract.address, 1000 * 10**6)  # 1000 USDC (assuming 6 decimals)
    
    # Step 5: Make a payment
    payment_id = make_payment(refund_contract, recipient_address, 100 * 10**6, address)  # 100 USDC, refund to self
    
    # Step 6: Early withdrawal demo
    payment_ids = [payment_id]
    withdrawal_amounts = [50 * 10**6]  # Withdraw 50 USDC
    fee_amount = 5 * 10**6  # 5 USDC fee
    expiry = int(time.time()) + 3600  # Valid for 1 hour
    
    salt, v, r, s = sign_early_withdrawal(
        refund_contract, 
        recipient_key, 
        payment_ids, 
        withdrawal_amounts, 
        fee_amount, 
        expiry
    )
    
    # --- Arbiter executes (approves early withdrawal based on signed request) ---
    execute_early_withdrawal(
        refund_contract,
        payment_ids,
        withdrawal_amounts,
        fee_amount,
        expiry,
        salt,
        recipient_address,
        v,
        r,
        s
    )
    
    # Step 7: Deposit arbiter funds
    deposit_arbiter_funds(refund_contract, 500 * 10**6)  # 500 USDC
    
    # Step 8: Refund a payment
    refund_by_arbiter(refund_contract, payment_id)
    
    print("RefundProtocol demo completed successfully!")

if __name__ == "__main__":
    main()
