import unittest
from kvm_nested_host import (node_tls_gateway_profile,TLS_GATEWAY_CHECKPOINT_FLAGS,TLS_GATEWAY_RECOVERY_FLAGS,TLS_GATEWAY_TIMINGS,validate_tls_gateway_checkpoint,validate_tls_gateway_recovery)

def checkpoint():
    return {**{k:True for k in TLS_GATEWAY_CHECKPOINT_FLAGS},'fixture_http_pacing_ms':50,'verified_real_guest_generations_before_cold':3,'policy_revision':2,**dict(zip(TLS_GATEWAY_TIMINGS,(100.0,200.0,120.0,250.0))),'production_slo_or_full_tls_qualification_claim':False,'physical_policy_media_fault_or_complete_dos_claim':False}
class TLSGatewayTests(unittest.TestCase):
    def test_fixed_artifact_and_exclusive_modifier(self):
        node_tls_gateway_profile(True,False,None,False,False,True,'gateway')
        for args in ((False,False,None,False,False,True,'gateway'),(True,True,None,False,False,True,'gateway'),(True,False,'pre-file',False,False,True,'gateway'),(True,False,None,True,False,True,'gateway'),(True,False,None,False,True,True,'gateway'),(True,False,None,False,False,True,None),(False,False,None,False,False,False,'gateway')):
            with self.assertRaises(ValueError):node_tls_gateway_profile(*args)
        node_tls_gateway_profile(False,True,'pre-file',True,True,False,None)
    def test_exact_semantics_and_no_private_material(self):
        good=checkpoint();validate_tls_gateway_checkpoint(good)
        for k,v in good.items():
            if type(v) is bool:
                with self.assertRaises(AssertionError):validate_tls_gateway_checkpoint(dict(good,**{k:not v}))
            elif type(v) is int:
                for n in (True,v+1):
                    with self.assertRaises(AssertionError):validate_tls_gateway_checkpoint(dict(good,**{k:n}))
        with self.assertRaises(AssertionError):validate_tls_gateway_checkpoint(dict(good,token='secret'))
    def test_independent_observation_timings_not_slo(self):
        good=checkpoint()
        for k in TLS_GATEWAY_TIMINGS:
            for v in (True,-1,float('nan'),float('inf'),40000):
                with self.assertRaises(AssertionError):validate_tls_gateway_checkpoint(dict(good,**{k:v}))
        with self.assertRaises(AssertionError):validate_tls_gateway_checkpoint(dict(good,switch_to_binding_observed_ms=201))
        with self.assertRaises(AssertionError):validate_tls_gateway_checkpoint(dict(good,switch_to_old_execution_empty_observed_ms=251))
    def test_cold_current_policy_no_rollback_or_guest_revival(self):
        good={k:True for k in TLS_GATEWAY_RECOVERY_FLAGS};validate_tls_gateway_recovery(good)
        for k in good:
            with self.assertRaises(AssertionError):validate_tls_gateway_recovery(dict(good,**{k:False}))
        with self.assertRaises(AssertionError):validate_tls_gateway_recovery(dict(good,private_receipt={}))
if __name__=='__main__':unittest.main()
