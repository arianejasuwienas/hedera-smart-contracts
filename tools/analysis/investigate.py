from evmdasm import EvmBytecode
import argparse
import requests

def fetch_contract_bytecode(mirror_node_url, contract_id):
    url = f'{mirror_node_url}/api/v1/contracts/{contract_id}'
    response = requests.get(url)

    if response.status_code == 200:
        bytecode = response.json().get('runtime_bytecode')
        if bytecode:
            address_detected = False
            method_detected = False
            param_detected = False
            call_detected = False

            evm_bytecode = EvmBytecode(bytecode)
            disassembled_code = evm_bytecode.disassemble()
            for instruction in disassembled_code:
                if instruction.operand == '0167':
                    address_detected = True
                # print(f"{instruction.address}: {instruction.name} {instruction.operand if instruction.operand else ''}")
                # | createFungibleToken((string,string,address,string,bool,int64,bool,(uint256,(bool,address,bytes,bytes,address))[],(int64,address,int64)),int64,int32)                                                                                            | 0x0fb65bf3 |
                # | createFungibleTokenWithCustomFees((string,string,address,string,bool,int64,bool,(uint256,(bool,address,bytes,bytes,address))[],(int64,address,int64)),int64,int32,(int64,address,bool,bool,address)[],(int64,int64,int64,int64,bool,address)[]) | 0x2af0c59a |
                # | createNonFungibleToken((string,string,address,string,bool,int64,bool,(uint256,(bool,address,bytes,bytes,address))[],(int64,address,int64)))                                                                                                     | 0xea83f293 |
                # | createNonFungibleTokenWithCustomFees((string,string,address,string,bool,int64,bool,(uint256,(bool,address,bytes,bytes,address))[],(int64,address,int64)),(int64,address,bool,bool,address)[],(int64,int64,int64,address,bool,address)[])        | 0xabb54eb5 |
                if instruction.operand in ['0fb65bf3', '2af0c59a', 'ea83f293', 'abb54eb5']:
                    method_detected = True
                if instruction.operand == '03' and instruction.name == 'PUSH1':
                    param_detected = True
                if instruction.name == 'CALL':
                    call_detected = True
            if address_detected and call_detected:
                print('Usage of Hedera address 0x167 detected. Calls to this address may have been possibly made')
            if method_detected:
                print('Usage of Hedera method creating token selector detected. Calls using this method may have been possibly made')
            if param_detected and address_detected and method_detected:
                print('Possibile usage of Hedera parameter KeyValueType.SECP256K1 selector detected. Calls with this param may have been possibly made')
        else:
            print('No bytecode found for the specified contract ID.')
    else:
        print(f'Failed to fetch bytecode. Status code: {response.status_code}')
        print('Response:', response.text)


def main():
    parser = argparse.ArgumentParser(description='Fetch bytecode of a smart contract from Hedera network')
    parser.add_argument('contract_id', help='ID of the smart contract')
    parser.add_argument('--previewnet', action='store_true', help='Use the Previewnet Mirror Node URL')
    parser.add_argument('--testnet', action='store_true', help='Use the Testnet Mirror Node URL')
    args = parser.parse_args()
    mirror_node_url = 'https://mainnet.mirrornode.hedera.com'
    if args.previewnet:
        mirror_node_url = 'https://previewnet.mirrornode.hedera.com'
    elif args.testnet:
        mirror_node_url = 'https://testnet.mirrornode.hedera.com'
    fetch_contract_bytecode(mirror_node_url, args.contract_id)

if __name__ == "__main__":
    main()
