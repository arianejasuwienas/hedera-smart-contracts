"""
Detector to find instances where `ecrecover` is used in Solidity contracts.
"""
from pprint import pprint
from slither.core.declarations import Function, Contract
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import Node, NodeType
from slither.slithir.operations import SolidityCall, LowLevelCall, HighLevelCall, Assignment, Call, InternalCall
from slither.core.variables.state_variable import StateVariable
from slither.slithir.variables.reference import ReferenceVariable
from slither.slithir.variables.constant import Constant
from slither.utils.output import Output
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.declarations import SolidityFunction
from eth_utils import keccak
from collections.abc import Iterable

class PrecompileCall(AbstractDetector):
    ARGUMENT = 'detect-hedera-precompile'
    HELP = 'Detects usage of calls to the Hedera precompile address in smart contract functions.'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://docs.hedera.com/hedera/core-concepts/smart-contracts/compiling-smart-contracts#hedera-token-service"
    WIKI_TITLE = "Usage of Hedera Precompile"
    WIKI_DESCRIPTION = "This detector identifies instances where smart contracts make calls to the Hedera precompile address (0x167)."
    WIKI_RECOMMENDATION = "Ensure that calls to the Hedera precompile address are securely handled and verified to prevent misuse or unintended behavior."
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract TokenCreateContract is HederaTokenService, ExpiryHelper, KeyHelper {
    function createFungibleTokenWithSECP256K1AdminKeyPublic(address treasury, bytes memory adminKey) public payable {
        IHederaTokenService.TokenKey[] memory keys = new IHederaTokenService.TokenKey[](5);
        keys[0] = getSingleKey(KeyType.ADMIN, KeyType.PAUSE, KeyValueType.SECP256K1, adminKey);
        IHederaTokenService.Expiry memory expiry = IHederaTokenService.Expiry(0, treasury, 8000000);
        IHederaTokenService.HederaToken memory token = IHederaTokenService.HederaToken(
            "tokenName", "tokenSymbol", treasury, "memo", true, 10000, false, keys, expiry
        );
        HederaTokenService.createFungibleToken(token, 10000, 8);
    }
}
```
"""
    ADDRESS_TO_DETECT = "0x167"

    def address_const_called_by_value(self, ir, address_vars):
        if not hasattr(ir, "destination"):
            return False
        if str(ir.destination) in address_vars: # Called parameter with value
            return True
        return isinstance(ir.destination, Constant) and str(ir.destination.value) == ADDRESS_TO_DETECT # Called constant by value

    def get_entrypoint(self, function, path = []):
        path.append(f"{function.contract.name}.{function.full_name}")
        if str(function.visibility) in ["external", "public"]:
            return path
        if len(path) == 10:
            return None
        for contract in self.slither.contracts:
            for compare in contract.functions_and_modifiers:
                for node in compare.nodes:
                    for ir in node.irs:
                        if isinstance(ir, (InternalCall)):
                            if ir.function_name == function.name and ir.contract_name == function.contract.name and self.get_entrypoint(compare, path):
                                return path
        return None

    def _detect(self):
        results = []
        for contract in self.slither.contracts:
            address_vars = [self.ADDRESS_TO_DETECT]
            for var in contract.state_variables:
                if str(var.expression) == f"address({self.ADDRESS_TO_DETECT})" and var.name not in address_vars:
                    address_vars.append(var.name)

            for function in contract.functions_and_modifiers:
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, (HighLevelCall, LowLevelCall)):
                            if self.address_const_called_by_value(ir, address_vars):
                                entrypoint = self.get_entrypoint(function)
                                if entrypoint is not None and function.contract.name in str(node.source_mapping.filename.short):
                                    entrypoint_string = ''
                                    if entrypoint[::-1][0] != f"{function.contract.name}.{function.full_name}":
                                        entrypoint_string = f" Start investigating in {entrypoint[::-1][0]}."
                                    call_type = "variable"
                                    if isinstance(ir.destination, Constant):
                                        call_type = "direct value"
                                    info = [f"Function {function.contract.name}.{function.full_name} calls the address 0x167 via {call_type} '{ir.destination}'.{entrypoint_string} \n"]
                                    json_data = self.generate_result(info)
                                    results.append(json_data)
        return results
