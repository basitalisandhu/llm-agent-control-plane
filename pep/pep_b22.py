"""Strict provenance variant, v2.2: designator tokens inside ANY argument fail closed, and the check runs even when
another argument already failed, so an unsourced designator always makes the failure non-escalable."""
from pep22 import PEPExecutor, PEPState, FunctionCall, _values_of, _TOKEN_RE, canon


class PEPExecutorStrict(PEPExecutor):
    def _extra_provenance_failures(self, st: PEPState, call: FunctionCall):
        out = []
        for arg, val in call.args.items():
            for v in _values_of(val):
                if isinstance(v, str):
                    for tok in _TOKEN_RE.findall(v):
                        ct = canon(tok)
                        if ct and not self._sourced(st, ct):
                            out.append(("token", arg, f"designator '{tok}' in argument '{arg}' is not sourced from the request or from trusted data (strict)"))
        return out
