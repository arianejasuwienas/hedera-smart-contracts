"""
Detector to find instances where `ecrecover` is used in Solidity contracts.
"""
from slither.core.declarations import Contract
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.cfg.node import Node
from slither.slithir.operations import SolidityCall, LowLevelCall, HighLevelCall, Assignment
from slither.slithir.operations.call import Call
from slither.utils.output import Output
from slither.core.cfg.node import NodeType
from slither.core.expressions import CallExpression, Identifier
from slither.core.declarations import SolidityFunction
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations.enum_contract import EnumContract
from slither.utils.function import get_function_id
import re

class Secp256k1KeyUsage(AbstractDetector):
    TARGET_ADDRESS = "address(0x167)"
    SEARCHED_VALUE = 'SECP256K1'
    SELECTOR_STRING = 'getTokenKey(address,uint256)'

    ARGUMENT = 'detect-secp256k1_key'
    HELP = 'Detects direct calls to the method `getTokenKey(address,uint256)` on address 0x167, specifically utilizing the parameter value SECP256K1.'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://docs.hedera.com/hedera/core-concepts/keys-and-signatures"
    WIKI_TITLE = "Usage of secp256k1_key"
    WIKI_DESCRIPTION = "This detector identifies instances where the `getTokenKey(address,uint256)` method is called on address 0x167 with the `SECP256K1` parameter value."
    WIKI_RECOMMENDATION = "Consider using Hedera-supported key types such as Ed25519, as `ecrecover` expects ECDSA keys!"
    WIKI_EXPLOIT_SCENARIO = """
    ```solidity
    import "./IHRC.sol";
    import "./HederaTokenService.sol";
    import "./IHederaTokenService.sol";
    import "./KeyHelper.sol";
    contract HTSContract is KeyHelper { {
        function secp256k1() external {
            supplyContract = 0x0000000000000000000000000000000000000000;
            getSingleKey(KeyType.WIPE, KeyValueType.SECP256K1, '0x0000');
        }
    }
    ```
    """
    def _detect(self):
        results = []

        target_address_called = False
        search_param_used = False

        for function in self.extract_all_functions(self.compilation_unit.contracts_derived):
            search_param_used = search_param_used or self.is_search_value_utilised(function)
            for ir in self.extract_all_irs(function):
                if self.is_target_address_called(ir) and self.are_params_encoded_in_supported_way(ir):
                    target_address_called = target_address_called or self.is_required_method_called(ir, function)

        if target_address_called and search_param_used:
            info = [f"HTS method getTokenKey with secp256k1_key may be possibly called.\n"]
            result = self.generate_result(info)
            results.append(result)

        return results

    def is_search_value_utilised(self, function):
        for node in function.nodes:
            for ir in node.irs:
                if hasattr(ir, '_variable_left') and hasattr(ir, '_variable_right') and ir._variable_right == self.SEARCHED_VALUE and isinstance(ir._variable_left, EnumContract):
                    return True
        return False

    def is_target_address_called(self, ir):
        if not isinstance(ir, (LowLevelCall, HighLevelCall, Call)) or not hasattr(ir, "destination") or not isinstance(ir.destination, StateVariable):
            return False
        for var in ir.destination.contract.state_variables:
            if str(ir.destination) == var.name and str(var.expression) == self.TARGET_ADDRESS:
                return True
        return False

    def are_params_encoded_in_supported_way(self, ir):
        return re.search(r"abi\.encodeWithSelector\(([^)]+)\)", str(ir.expression))

    def is_required_method_called(self, ir, function):
        if hasattr(ir, 'expression') and hasattr(ir.expression, '_arguments') and ir.expression._arguments and hasattr(ir.expression._arguments[0], '_arguments') and ir.expression._arguments[0]._arguments:
            first_arg = ir.expression._arguments[0]._arguments[0]
            if hasattr(first_arg, '_expression') and hasattr(first_arg._expression, 'type'):
                return self.SELECTOR_STRING in first_arg._expression.type
        return False

    def extract_all_functions(self, contracts_derived):
        result = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions + contract.modifiers:
                result.append(function)
        return result

    def extract_all_irs(self, function):
        result = []
        for node in function.nodes:
            for ir in node.irs:
                result.append(ir)
        return result
