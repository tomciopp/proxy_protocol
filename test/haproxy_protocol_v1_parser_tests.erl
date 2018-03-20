-module(haproxy_protocol_v1_parser_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").

tcp4_success_test() ->
  Packet = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nGET / HTTP/1.1\r",
  {ok, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), {192, 168, 0, 11}),
  ?assertEqual(maps:get(src_address, Proxy), {192, 168, 0, 1}),
  ?assertEqual(maps:get(dest_port, Proxy), 443),
  ?assertEqual(maps:get(src_port, Proxy), 56324),
  ?assertEqual(maps:get(inet, Proxy), "TCP4"),
  ?assertEqual(maps:get(vsn, Proxy), "1").

tcp4_address_failure_test() ->
  Packet = "PROXY TCP4 192.1638.0.1 192.168.0.11 56324 443\r\nGET / HTTP/1.1\r",
  {error, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"192.1638.0.1 192.168.0.11 56324 443\r\nGET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), undefined),
  ?assertEqual(maps:get(src_address, Proxy), undefined),
  ?assertEqual(maps:get(dest_port, Proxy), undefined),
  ?assertEqual(maps:get(src_port, Proxy), undefined),
  ?assertEqual(maps:get(inet, Proxy), "TCP4"),
  ?assertEqual(maps:get(vsn, Proxy), "1").

tcp4_port_failure_test() ->
  Packet = "PROXY TCP4 192.168.0.1 192.168.0.11 1111111 443\r\nGET / HTTP/1.1\r",
  {error, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"1111111 443\r\nGET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), {192, 168, 0, 11}),
  ?assertEqual(maps:get(src_address, Proxy), {192, 168, 0, 1}),
  ?assertEqual(maps:get(dest_port, Proxy), undefined),
  ?assertEqual(maps:get(src_port, Proxy), undefined),
  ?assertEqual(maps:get(inet, Proxy), "TCP4"),
  ?assertEqual(maps:get(vsn, Proxy), "1").

tcp6_success_test() ->
  Packet = "PROXY TCP6 2001:0db8:0000:0042:0000:8a2e:0370:7334 2001:0db8:0000:0042:0000:8a2e:0370:7335 4124 443\r\nGET / HTTP/1.1\r",
  {ok, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), {8193, 3512, 0, 66, 0, 35374, 880, 29493}),
  ?assertEqual(maps:get(src_address, Proxy), {8193, 3512, 0, 66, 0, 35374, 880, 29492}),
  ?assertEqual(maps:get(dest_port, Proxy), 443),
  ?assertEqual(maps:get(src_port, Proxy), 4124),
  ?assertEqual(maps:get(inet, Proxy), "TCP6"),
  ?assertEqual(maps:get(vsn, Proxy), "1").

tcp6_address_failure_test() ->
  Packet = "PROXY TCP6 2001:0db8:0000:0042:0000:8a2e:0370:7334 2001:0db8:00;0:0042:0000:8a2e:0370:7335 4124 443\r\nGET / HTTP/1.1\r",
  {error, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"2001:0db8:00;0:0042:0000:8a2e:0370:7335 4124 443\r\nGET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), undefined),
  ?assertEqual(maps:get(src_address, Proxy), {8193, 3512, 0, 66, 0, 35374, 880, 29492}),
  ?assertEqual(maps:get(dest_port, Proxy), undefined),
  ?assertEqual(maps:get(src_port, Proxy), undefined),
  ?assertEqual(maps:get(inet, Proxy), "TCP6"),
  ?assertEqual(maps:get(vsn, Proxy), "1").

tcp6_port_failure_test() ->
  Packet = "PROXY TCP6 2001:0db8:0000:0042:0000:8a2e:0370:7334 2001:0db8:0000:0042:0000:8a2e:0370:7335 4124 foo\r\nGET / HTTP/1.1\r",
  {error, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"foo\r\nGET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), {8193,3512,0,66,0,35374,880,29493}),
  ?assertEqual(maps:get(src_address, Proxy), {8193, 3512, 0, 66, 0, 35374, 880, 29492}),
  ?assertEqual(maps:get(dest_port, Proxy), undefined),
  ?assertEqual(maps:get(src_port, Proxy), 4124),
  ?assertEqual(maps:get(inet, Proxy), "TCP6"),
  ?assertEqual(maps:get(vsn, Proxy), "1").

unknown_extra_data_test() ->
  Packet = "PROXY UNKNOWN 4124 443\r\nGET / HTTP/1.1\r",
  {ok, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), undefined),
  ?assertEqual(maps:get(src_address, Proxy), undefined),
  ?assertEqual(maps:get(dest_port, Proxy), undefined),
  ?assertEqual(maps:get(src_port, Proxy), undefined),
  ?assertEqual(maps:get(inet, Proxy), "UNKNOWN"),
  ?assertEqual(maps:get(vsn, Proxy), "1").

unknown_crlf_test() ->
  Packet = "PROXY UNKNOWN\r\nGET / HTTP/1.1\r",
  {ok, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), undefined),
  ?assertEqual(maps:get(src_address, Proxy), undefined),
  ?assertEqual(maps:get(dest_port, Proxy), undefined),
  ?assertEqual(maps:get(src_port, Proxy), undefined),
  ?assertEqual(maps:get(inet, Proxy), "UNKNOWN"),
  ?assertEqual(maps:get(vsn, Proxy), "1").
