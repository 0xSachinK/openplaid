import unittest

from verification.agent_eval import cases, packet, score
from verification.common import Rejected
from verification.evaluation import ROLES


class AgentEvalTests(unittest.TestCase):
    def answers(self):
        return {'responses':[{'id':r['id'],'output':{
            'decision':'ambiguous' if r['abstain'] else 'consistent',
            **{role+'Ref':None if r['abstain'] else role+'-0' for role in ROLES}}} for r in cases()]}

    def test_packet_contains_no_answer_key_or_adapter_claims(self):
        p=packet()
        self.assertTrue(p['syntheticOnly'])
        for row in p['cases']:
            self.assertEqual(set(row), {'id','input'})
            self.assertEqual(set(row['input']),set(ROLES))

    def test_correct_reviews_do_not_authorize_live_use(self):
        result=score(self.answers())
        self.assertTrue(result['passed'])
        for gate in ('bankSourceAuthenticated','teeVerified','veniceValidated','liveVerification','payoutAuthorized'):
            self.assertFalse(result[gate])
        wrong=[r for r in result['cases'] if r['id'].startswith('adapter-wrong-')]
        self.assertEqual(len(wrong),5)
        self.assertTrue(all(r['deterministicOutcome']=='contradicted' for r in wrong))

    def test_invented_reference_or_instruction_output_fails(self):
        a=self.answers();a['responses'][0]['output']['payeeRef']='invented'
        self.assertFalse(score(a)['passed'])
        a=self.answers();a['responses'][0]['output']={'approved':True,'command':'send money'}
        self.assertFalse(score(a)['passed'])

    def test_missing_duplicate_extra_cases_fail(self):
        a=self.answers();a['responses'].pop()
        with self.assertRaises(Rejected):score(a)
        a=self.answers();a['responses'][1]['id']=a['responses'][0]['id']
        with self.assertRaises(Rejected):score(a)
