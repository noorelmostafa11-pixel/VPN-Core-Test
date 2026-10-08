"""Alternate import syntax preserves source identity and connection settings."""
import base64
import json
import os
import pathlib
import subprocess
import unittest
from urllib.parse import quote

ROOT=pathlib.Path(__file__).resolve().parents[1]
PROBE=os.environ.get('VPN_CORE_URI_SOURCE_PROBE',str(ROOT/'bin/uri-source-probe'))
PUBLIC_KEY=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
BASE='vless://12345678-1234-4567-9234-567812345678@localhost:443?'

class UriCompatibilityTests(unittest.TestCase):
    def probe(self,query):
        uri=BASE+query
        process=subprocess.run([PROBE],input=json.dumps({'uri':uri})+'\n',capture_output=True,text=True,check=True,timeout=10)
        return json.loads(process.stdout)

    def extra(self,text):
        return self.probe('type=xhttp&security=tls&extra='+quote(text,safe=''))

    def accepted(self,row):
        self.assertNotIn('error',row)
        self.assertTrue(row['config_valid'])
        self.assertFalse(row['missing_features'])
        self.assertTrue(row['source_uri_preserved'])

    def test_valid_json_keeps_plus_percent_and_every_field(self):
        value={'headers':{'x-note':'a+b%2Fc'},'xPaddingBytes':'100-300','xmux':{'maxConcurrency':'1-3'}}
        original=json.dumps(value)
        row=self.extra(original);self.accepted(row)
        self.assertEqual(row['resolved_extra'],value)
        self.assertEqual(row['original_options']['extra'],original)
        self.assertNotIn('uri_compatibility',row)

    def test_plus_whitespace_preserves_string_data_and_numeric_exponent(self):
        original='{"headers":+{"x-note":+"a+b%2Fc"},+"xPaddingBytes":+100}'
        row=self.extra(original);self.accepted(row)
        self.assertEqual(row['resolved_extra'],{'headers':{'x-note':'a+b%2Fc'},'xPaddingBytes':100})
        self.assertEqual(row['original_options']['extra'],original)
        self.assertEqual(row['uri_compatibility'],['XHTTP_EXTRA_PLUS_WHITESPACE'])
        from_text='{"xPaddingBytes":+1e+2}'
        row=self.extra(from_text);self.accepted(row)
        self.assertEqual(row['resolved_extra']['xPaddingBytes'],100)

    def test_single_quoted_object_preserves_escaped_apostrophe_and_double_quote(self):
        original="{'headers': {'x-note': 'a+b says \"hi\" and \\'ok\\''}, 'xPaddingBytes': '100-300'}"
        row=self.extra(original);self.accepted(row)
        self.assertEqual(row['resolved_extra']['headers']['x-note'],'a+b says "hi" and \'ok\'')
        self.assertEqual(row['original_options']['extra'],original)
        self.assertEqual(row['uri_compatibility'],['XHTTP_EXTRA_SINGLE_QUOTES'])

    def test_double_encoding_decodes_object_without_decoding_its_strings(self):
        value={'headers':{'x-note':'a+b%2Fc'},'xPaddingBytes':'100-300'}
        encoded=quote(json.dumps(value),safe='')
        row=self.extra(encoded);self.accepted(row)
        self.assertEqual(row['resolved_extra'],value)
        self.assertEqual(row['original_options']['extra'],encoded)
        self.assertEqual(row['uri_compatibility'],['XHTTP_EXTRA_DOUBLE_URL_ENCODING'])

    def test_single_quotes_and_plus_whitespace_can_coexist(self):
        original="{'headers':+{'x-note':+'a+b'},+'xPaddingBytes':+'100-300'}"
        row=self.extra(original);self.accepted(row)
        self.assertEqual(row['resolved_extra'],{'headers':{'x-note':'a+b'},'xPaddingBytes':'100-300'})
        self.assertEqual(row['original_options']['extra'],original)
        self.assertEqual(row['uri_compatibility'],['XHTTP_EXTRA_QUOTES_AND_WHITESPACE'])

    def test_incomplete_or_non_object_extra_still_rejected(self):
        for text in ('{',"{'xPaddingBytes':",'[]','"{}"','{"noGRPCHeader": True}',"{'noGRPCHeader': __import__('os')}"):
            with self.subTest(text=text):
                self.assertEqual(self.extra(text)['reason_code'],'XHTTP_CONFIGURATION')

    def test_finalmask_is_preserved_and_not_discarded_when_malformed(self):
        row=self.probe('type=tcp&security=tls&fm=%7B')
        self.assertEqual(row['reason_code'],'CONFIG_VALIDATION_INVALID')
        original=json.dumps({'tcp':[{'type':'fragment','settings':{'packets':'tlshello','length':'100-200','delay':'1-2'}}]})
        row=self.probe('type=tcp&security=tls&fm='+quote(original,safe=''));self.accepted(row)
        self.assertEqual(row['original_options']['fm'],original)
        self.assertNotIn('uri_compatibility',row)

    def test_corrupted_none_suffix_keeps_original_source_and_other_options(self):
        for text in ('none=source-label','none@source-label','none\u00ace=source-label'):
            with self.subTest(text=text):
                row=self.probe('type=ws&security=tls&path=%2Fkeep&encryption='+quote(text,safe=''));self.accepted(row)
                self.assertEqual(row['cipher'],'none')
                self.assertEqual(row['transport'],'websocket')
                self.assertEqual(row['original_options']['encryption'],text)
                self.assertEqual(row['original_options']['path'],'/keep')
                self.assertEqual(row['uri_compatibility'],['VLESS_NONE_SUFFIX'])

    def test_unregistered_encryption_is_not_guessed(self):
        for text in ('none-aes','none.aes','none;other=1','aes-256-gcm'):
            with self.subTest(text=text):
                row=self.probe('encryption='+quote(text,safe=''))
                self.assertEqual(row['reason_code'],'VLESS_ENCRYPTION_INVALID')

    def test_tcp_fragment_suffix_only_applies_to_vless_reality(self):
        row=self.probe('security=reality&pbk='+PUBLIC_KEY+'&type=tcp%23source-label');self.accepted(row)
        self.assertEqual(row['transport'],'raw')
        self.assertEqual(row['original_options']['type'],'tcp#source-label')
        self.assertEqual(row['uri_compatibility'],['REALITY_TCP_FRAGMENT_SUFFIX'])
        self.assertEqual(self.probe('security=tls&type=tcp%23source-label')['reason_code'],'TRANSPORT_NAME_INVALID')

    def test_semicolon_key_aliases_keep_originals_and_resolve_required_fields(self):
        row=self.probe('security=reality&type=tcp&;pbk='+PUBLIC_KEY+'&;sid=abcd&;sni=example.test&;fp=chrome');self.accepted(row)
        self.assertEqual(row['resolved_public_key'],PUBLIC_KEY)
        self.assertEqual(row['resolved_short_id'],'abcd')
        self.assertEqual(row['resolved_server_name'],'example.test')
        self.assertEqual(row['original_options'][';pbk'],PUBLIC_KEY)
        self.assertNotIn('pbk',row['original_options'])
        self.assertEqual(row['uri_compatibility'],['REALITY_SEMICOLON_FIELD_ALIASES'])

    def test_semicolon_alias_cannot_replace_explicit_key_or_security(self):
        other=base64.urlsafe_b64encode(bytes(reversed(range(32)))).decode().rstrip('=')
        row=self.probe('security=reality&pbk='+PUBLIC_KEY+'&;pbk='+other);self.accepted(row)
        self.assertEqual(row['resolved_public_key'],PUBLIC_KEY)
        self.assertNotIn('uri_compatibility',row)
        self.assertEqual(self.probe('security=reality&pbk=invalid&;pbk='+PUBLIC_KEY)['reason_code'],'REALITY_PUBLIC_KEY_INVALID')
        row=self.probe('security=tls&;pbk='+PUBLIC_KEY);self.accepted(row)
        self.assertEqual(row['security'],'tls')
        self.assertEqual(row['resolved_public_key'],'')
        self.assertNotIn('uri_compatibility',row)

    def test_missing_key_and_invalid_short_id_stay_rejected(self):
        self.assertEqual(self.probe('security=reality')['reason_code'],'REALITY_PUBLIC_KEY_INVALID')
        self.assertEqual(self.probe('security=reality&;pbk='+PUBLIC_KEY+'&;sid=not-hex')['reason_code'],'REALITY_SHORT_ID_INVALID')

if __name__=='__main__':unittest.main(verbosity=2)
