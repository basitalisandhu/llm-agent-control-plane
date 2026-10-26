"""Strict provenance variant for Track B: designator tokens inside ANY argument fail closed
(must be sourced from the request or typed data), which defeats obfuscated injections that make
the model reconstruct a designator absent from the untrusted corpus."""
from pep import PEPExecutor, PEPState, FunctionCall, _values_of, _TOKEN_RE, canon


class PEPExecutorStrict(PEPExecutor):
    def _provenance_check(self, st: PEPState, call: FunctionCall):
        ok, why, kind = super()._provenance_check(st, call)
        if not ok:
            return ok, why, kind
        for arg, val in call.args.items():
            for v in _values_of(val):
                if isinstance(v, str):
                    for tok in _TOKEN_RE.findall(v):
                        ct = canon(tok)
                        if ct and not self._sourced(st, ct):
                            return False, f"designator '{tok}' in argument '{arg}' is not sourced from the request or from trusted data (strict)", "token"
        return True, "", ""
