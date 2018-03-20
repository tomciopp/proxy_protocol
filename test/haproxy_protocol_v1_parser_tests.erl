-module(haproxy_protocol_v1_parser_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").

-include("proxy.hrl").

tcp4_success_test() ->
  Packet = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nGET / HTTP/1.1\r",
  {ok, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(Proxy#proxy.dest_address, {192, 168, 0, 11}),
  ?assertEqual(Proxy#proxy.src_address, {192, 168, 0, 1}),
  ?assertEqual(Proxy#proxy.dest_port, 443),
  ?assertEqual(Proxy#proxy.src_port, 56324),
  ?assertEqual(Proxy#proxy.inet, "TCP4"),
  ?assertEqual(Proxy#proxy.vsn, "1").

tcp4_address_failure_test() ->
  Packet = "PROXY TCP4 192.1638.0.1 192.168.0.11 56324 443\r\nGET / HTTP/1.1\r",
  {error, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"192.1638.0.1 192.168.0.11 56324 443\r\nGET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(Proxy#proxy.dest_address, undefined),
  ?assertEqual(Proxy#proxy.src_address, undefined),
  ?assertEqual(Proxy#proxy.dest_port, undefined),
  ?assertEqual(Proxy#proxy.src_port, undefined),
  ?assertEqual(Proxy#proxy.inet, "TCP4"),
  ?assertEqual(Proxy#proxy.vsn, "1").

tcp4_port_failure_test() ->
  Packet = "PROXY TCP4 192.168.0.1 192.168.0.11 1111111 443\r\nGET / HTTP/1.1\r",
  {error, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"1111111 443\r\nGET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(Proxy#proxy.dest_address, {192, 168, 0, 11}),
  ?assertEqual(Proxy#proxy.src_address, {192, 168, 0, 1}),
  ?assertEqual(Proxy#proxy.dest_port, undefined),
  ?assertEqual(Proxy#proxy.src_port, undefined),
  ?assertEqual(Proxy#proxy.inet, "TCP4"),
  ?assertEqual(Proxy#proxy.vsn, "1").

tcp6_success_test() ->
  Packet = "PROXY TCP6 2001:0db8:0000:0042:0000:8a2e:0370:7334 2001:0db8:0000:0042:0000:8a2e:0370:7335 4124 443\r\nGET / HTTP/1.1\r",
  {ok, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(Proxy#proxy.dest_address, {8193, 3512, 0, 66, 0, 35374, 880, 29493}),
  ?assertEqual(Proxy#proxy.src_address, {8193, 3512, 0, 66, 0, 35374, 880, 29492}),
  ?assertEqual(Proxy#proxy.dest_port, 443),
  ?assertEqual(Proxy#proxy.src_port, 4124),
  ?assertEqual(Proxy#proxy.inet, "TCP6"),
  ?assertEqual(Proxy#proxy.vsn, "1").

tcp6_address_failure_test() ->
  Packet = "PROXY TCP6 2001:0db8:0000:0042:0000:8a2e:0370:7334 2001:0db8:00;0:0042:0000:8a2e:0370:7335 4124 443\r\nGET / HTTP/1.1\r",
  {error, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"2001:0db8:00;0:0042:0000:8a2e:0370:7335 4124 443\r\nGET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(Proxy#proxy.dest_address, undefined),
  ?assertEqual(Proxy#proxy.src_address, {8193, 3512, 0, 66, 0, 35374, 880, 29492}),
  ?assertEqual(Proxy#proxy.dest_port, undefined),
  ?assertEqual(Proxy#proxy.src_port, undefined),
  ?assertEqual(Proxy#proxy.inet, "TCP6"),
  ?assertEqual(Proxy#proxy.vsn, "1").

tcp6_port_failure_test() ->
  Packet = "PROXY TCP6 2001:0db8:0000:0042:0000:8a2e:0370:7334 2001:0db8:0000:0042:0000:8a2e:0370:7335 4124 foo\r\nGET / HTTP/1.1\r",
  {error, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"foo\r\nGET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(Proxy#proxy.dest_address, {8193,3512,0,66,0,35374,880,29493}),
  ?assertEqual(Proxy#proxy.src_address, {8193, 3512, 0, 66, 0, 35374, 880, 29492}),
  ?assertEqual(Proxy#proxy.dest_port, undefined),
  ?assertEqual(Proxy#proxy.src_port, 4124),
  ?assertEqual(Proxy#proxy.inet, "TCP6"),
  ?assertEqual(Proxy#proxy.vsn, "1").

unknown_extra_data_test() ->
  Packet = "PROXY UNKNOWN 4124 443\r\nGET / HTTP/1.1\r",
  {ok, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(Proxy#proxy.dest_address, undefined),
  ?assertEqual(Proxy#proxy.src_address, undefined),
  ?assertEqual(Proxy#proxy.dest_port, undefined),
  ?assertEqual(Proxy#proxy.src_port, undefined),
  ?assertEqual(Proxy#proxy.inet, "UNKNOWN"),
  ?assertEqual(Proxy#proxy.vsn, "1").

unknown_crlf_test() ->
  Packet = "PROXY UNKNOWN\r\nGET / HTTP/1.1\r",
  {ok, Map} = haproxy_protocol_v1_parser:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(Proxy#proxy.dest_address, undefined),
  ?assertEqual(Proxy#proxy.src_address, undefined),
  ?assertEqual(Proxy#proxy.dest_port, undefined),
  ?assertEqual(Proxy#proxy.src_port, undefined),
  ?assertEqual(Proxy#proxy.inet, "UNKNOWN"),
  ?assertEqual(Proxy#proxy.vsn, "1").

