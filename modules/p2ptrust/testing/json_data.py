import base64 as __b64

one_correct = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "eyJtZXNzYWdlX3R5cGUiOiAicmVwb3J0IiwgImtleV90eXBlIjogImlwIiwgImtleSI6ICIxLjIuMy40MCIsIC'
    'JldmFsdWF0aW9uX3R5cGUiOiAic2NvcmVfY29uZmlkZW5jZSIsICJldmFsdWF0aW9uIjogeyAic2NvcmUiOiAwLjksICJjb25maWRl'
    'bmNlIjogMC42IH19"'
    '  }'
)


two_correctA = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "eyJtZXNzYWdlX3R5cGUiOiAicmVwb3J0IiwgImtleV90eXBlIjogImlwIiwgImtleSI6ICIxLjIuMy40MCIsIC'
    'JldmFsdWF0aW9uX3R5cGUiOiAic2NvcmVfY29uZmlkZW5jZSIsICJldmFsdWF0aW9uIjogeyAic2NvcmUiOiAwLjksICJjb25maWRl'
    'bmNlIjogMC42IH19"'
    '  }'
)
two_correctB = (
    '{'
    '    "reporter": "anotherreporterspeerid",'
    '    "report_time": 154800000,'
    '    "message": "eyJtZXNzYWdlX3R5cGUiOiAicmVwb3J0IiwgImtleV90eXBlIjogImlwIiwgImtleSI6ICIxLjIuMy41IiwgIm'
    'V2YWx1YXRpb25fdHlwZSI6ICJzY29yZV9jb25maWRlbmNlIiwgImV2YWx1YXRpb24iOiB7ICJzY29yZSI6IDAuOSwgImNvbmZpZGVu'
    'Y2UiOiAwLjYgfX0="'
    '  }'
)


invalid_json1 = '[}'
invalid_json2 = '{"key_type": "ip", "key": "1.2.3.40", "evaluation_type": "score_confidence"'
invalid_json3 = '{"key_type": "ip", "key": "1.2.3.40", "evaluation_type": "score_confidence}'


not_a_list = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "eyJrZXlfdHlwZSI6ICJpcCIsICJrZXkiOiAiMS4yLjMuNDAiLCAiZXZhbHVhdGlvbl90eXBlIjogInNjb3JlX2N'
    'vbmZpZGVuY2UiLCAiZXZhbHVhdGlvbiI6IHsgInNjb3JlIjogMC45LCAiY29uZmlkZW5jZSI6IDAuNiB9fQ=="'
    '  }'
)


empty_list = '[]'


missing_fields = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "message": "eyJrZXlfdHlwZSI6ICJpcCIsICJrZXkiOiAiMS4yLjMuNDAiLCAiZXZhbHVhdGlvbl90eXBlIjogInNjb3J'
    'lX2NvbmZpZGVuY2UiLCAiZXZhbHVhdGlvbiI6IHsgInNjb3JlIjogMC45LCAiY29uZmlkZW5jZSI6IDAuNiB9fQ=="'
    '  }'
)


too_many_fields = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "some_other_key": "a useless value",'
    '    "report_time": 154900000,'
    '    "message": "eyJrZXlfdHlwZSI6ICJpcCIsICJrZXkiOiAiMS4yLjMuNDAiLCAiZXZhbHVhdGlvbl90eXBlIjogInNjb3'
    'JlX2NvbmZpZGVuY2UiLCAiZXZhbHVhdGlvbiI6IHsgInNjb3JlIjogMC45LCAiY29uZmlkZW5jZSI6IDAuNiB9fQ=="'
    '  }'
)


wrong_time_string = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": "just_now",'
    '    "message": "eyJrZXlfdHlwZSI6ICJpcCIsICJrZXkiOiAiMS4yLjMuNDAiLCAiZXZhbHVhdGlvbl90eXBlIjogInNjb3JlX2'
    'NvbmZpZGVuY2UiLCAiZXZhbHVhdGlvbiI6IHsgInNjb3JlIjogMC45LCAiY29uZmlkZW5jZSI6IDAuNiB9fQ=="'
    '  }'
)
wrong_time_empty_string = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": "",'
    '    "message": "eyJrZXlfdHlwZSI6ICJpcCIsICJrZXkiOiAiMS4yLjMuNDAiLCAiZXZhbHVhdGlvbl90eXBlIjogInNjb3JlX2'
    'NvbmZpZGVuY2UiLCAiZXZhbHVhdGlvbiI6IHsgInNjb3JlIjogMC45LCAiY29uZmlkZW5jZSI6IDAuNiB9fQ=="'
    '  }'
)
wrong_time_negative = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": -3,'
    '    "message": "eyJrZXlfdHlwZSI6ICJpcCIsICJrZXkiOiAiMS4yLjMuNDAiLCAiZXZhbHVhdGlvbl90eXBlIjogInNjb3JlX2'
    'NvbmZpZGVuY2UiLCAiZXZhbHVhdGlvbiI6IHsgInNjb3JlIjogMC45LCAiY29uZmlkZW5jZSI6IDAuNiB9fQ=="'
    '  }'
)
wrong_time_float = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 2.5,'
    '    "message": "eyJrZXlfdHlwZSI6ICJpcCIsICJrZXkiOiAiMS4yLjMuNDAiLCAiZXZhbHVhdGlvbl90eXBlIjogInNjb3JlX2'
    'NvbmZpZGVuY2UiLCAiZXZhbHVhdGlvbiI6IHsgInNjb3JlIjogMC45LCAiY29uZmlkZW5jZSI6IDAuNiB9fQ=="'
    '  }'
)
wrong_time_future = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 2587122908,'
    '    "message": "eyJrZXlfdHlwZSI6ICJpcCIsICJrZXkiOiAiMS4yLjMuNDAiLCAiZXZhbHVhdGlvbl90eXBlIjogInNjb3JlX2'
    'NvbmZpZGVuY2UiLCAiZXZhbHVhdGlvbiI6IHsgInNjb3JlIjogMC45LCAiY29uZmlkZW5jZSI6IDAuNiB9fQ=="'
    '  }'
)


__message = b'{"message_type": "report", "key_type": "ip", "key": "1.2.3.40", "evaluation_type": "unknown type", "evaluation": ["eval1", "eval2"]}'
__b64m = __b64.b64encode(__message)
wrong_message_type = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)


__message = b'{"message_type": "report", "key_type": "you don\'t know this key type, sucker", "key": "1.2.3.40", "evaluation_type": "score_confidence", "evaluation": { "score": 0.9, "confidence": 0.6 }}'
__b64m = __b64.b64encode(__message)
wrong_message_key_type = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)


wrong_message_base64 = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "][bpsrt;hla;rkgty[a0rwg,m;aestrglk"'
    '  }'
)


__message = b'I am a terrible peer and I will not send you valid json'
__b64m = __b64.b64encode(__message)
wrong_message_json = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)

__message = b'{"message_type": "report", "key_type": "ip", "key": "1.2.3.40", "evaluation_type": "score_confidence", "evaluation": ["eval1", "eval2"]}'
__b64m = __b64.b64encode(__message)
wrong_message_eval_structure = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)


__message = b'{"message_type": "report", "key_type": "ip", "evaluation_type": "score_confidence", "evaluation":  { "score": 0.9, "confidence": 0.6 }}'
__b64m = __b64.b64encode(__message)
wrong_message_no_key = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)

__message = b'{"message_type": "report", "key_type": "ip", "key": "1.2.3.40", "surprise key": 42, "evaluation_type": "score_confidence", "evaluation":  { "score": 0.9, "confidence": 0.6 }}'
__b64m = __b64.b64encode(__message)
wrong_message_too_many_keys = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)

__message = b'{"message_type": "report", "key_type": "ip", "key": "2001:0db8:0000:0000:0000:ff00:0042:8329", "evaluation_type": "score_confidence", "evaluation":  { "score": 0.9, "confidence": 0.6 }}'
__b64m = __b64.b64encode(__message)
test_message_ipv6 = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)

__message = b'{"message_type": "report", "key_type": "ip", "key": "1.2.3.4", "evaluation_type": "score_confidence", "evaluation":  { "score": "zero", "confidence": 0.6 }}'
__b64m = __b64.b64encode(__message)
wrong_message_wrong_type_score1 = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)

__message = b'{"message_type": "report", "key_type": "ip", "key": "1.2.3.4", "evaluation_type": "score_confidence", "evaluation":  { "score": [], "confidence": 0.6 }}'
__b64m = __b64.b64encode(__message)
wrong_message_wrong_type_score2 = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)

__message = b'{"message_type": "report", "key_type": "ip", "key": "1.2.3.4", "evaluation_type": "score_confidence", "evaluation":  { "score": 0.9, "confidence": {} }}'
__b64m = __b64.b64encode(__message)
wrong_message_wrong_type_confidence = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)


__message = b'{"message_type": "report", "key_type": "ip", "key": "This is the IP address you are looking for", "evaluation_type": "score_confidence", "evaluation":  { "score": 0.9, "confidence": 0.6 }}'
__b64m = __b64.b64encode(__message)
wrong_message_wrong_type_ip = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)


__message = b'{"message_type": "report", "key_type": "ip", "key": "1.2.3.4", "evaluation_type": "score_confidence", "evaluation":  { "score": 1.00001, "confidence": 0.6 }}'
__b64m = __b64.b64encode(__message)
wrong_message_score_out_of_range = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)

__message = b'{"message_type": "report", "key_type": "ip", "key": "1.2.3.4", "evaluation_type": "score_confidence", "evaluation":  { "score": 0.9, "confidence": -3 }}'
__b64m = __b64.b64encode(__message)
wrong_message_confidence_out_of_range = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)

__message = b'{"message_type": "report", "key_type": "ip", "key": "1.2.3.7", "evaluation_type": "score_confidence", "evaluation":  null}'
__b64m = __b64.b64encode(__message)
ok_empty_report = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)

__message = b'{"message_type": "request", "key_type": "ip", "key": "1.2.3.4", "evaluation_type": "score_confidence"}'
__b64m = __b64.b64encode(__message)
ok_request = (
    '{'
    '    "reporter": "abcsakughroiauqrghaui",'
    '    "report_time": 154900000,'
    '    "message": "' + __b64m.decode() + '"'
    '  }'
)
