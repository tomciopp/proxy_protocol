-module(proxy_protocol_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").

-include("proxy.hrl").

v1_parser_test() ->
  Packet = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nGET / HTTP/1.1\r",
  {ok, Map} = proxy_protocol:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(Proxy#proxy.dest_address, {192, 168, 0, 11}),
  ?assertEqual(Proxy#proxy.src_address, {192, 168, 0, 1}),
  ?assertEqual(Proxy#proxy.dest_port, 443),
  ?assertEqual(Proxy#proxy.src_port, 56324),
  ?assertEqual(Proxy#proxy.inet, "TCP4"),
  ?assertEqual(Proxy#proxy.vsn, "1").

v2_parser_test() ->
  Signature = <<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 17>>,
  Length = <<0, 12>>,
  SrcAddress = <<127, 0, 0, 1>>,
  DestAddress = <<192, 168, 0, 1>>,
  SrcPort = <<1, 188>>,
  DestPort = <<1, 187>>,
  Request = <<"GET / HTTP/1.1\r\n">>,
  Packet = <<Signature/binary, Length/binary, SrcAddress/binary,
    DestAddress/binary, SrcPort/binary, DestPort/binary, Request/binary>>,

  {ok, Map} = proxy_protocol:parse(Packet),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r\n">>, maps:get(body, Map)),
  ?assertEqual(Proxy#proxy.dest_address, {192, 168, 0, 1}),
  ?assertEqual(Proxy#proxy.src_address, {127, 0, 0, 1}),
  ?assertEqual(Proxy#proxy.dest_port, 443),
  ?assertEqual(Proxy#proxy.src_port, 444),
  ?assertEqual(Proxy#proxy.inet, "TCP4"),
  ?assertEqual(Proxy#proxy.vsn, "2").

no_proxy_test() ->
  {ok, Map} = proxy_protocol:parse(<<"GET / HTTP/1.1\r\n">>),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r\n">>, maps:get(body, Map)),
  ?assertEqual(Proxy#proxy.dest_address, undefined),
  ?assertEqual(Proxy#proxy.src_address, undefined),
  ?assertEqual(Proxy#proxy.dest_port, undefined),
  ?assertEqual(Proxy#proxy.src_port, undefined),
  ?assertEqual(Proxy#proxy.inet, undefined),
  ?assertEqual(Proxy#proxy.vsn, undefined).