-module(haproxy_protocol_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").

v1_parser_test() ->
  Packet = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nGET / HTTP/1.1\r",
  {ok, Map} = haproxy_protocol:parse(list_to_binary(Packet)),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), {192, 168, 0, 11}),
  ?assertEqual(maps:get(src_address, Proxy), {192, 168, 0, 1}),
  ?assertEqual(maps:get(dest_port, Proxy), 443),
  ?assertEqual(maps:get(src_port, Proxy), 56324),
  ?assertEqual(maps:get(inet, Proxy), "TCP4"),
  ?assertEqual(maps:get(vsn, Proxy), "1").

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

  {ok, Map} = haproxy_protocol:parse(Packet),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r\n">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), {192, 168, 0, 1}),
  ?assertEqual(maps:get(src_address, Proxy), {127, 0, 0, 1}),
  ?assertEqual(maps:get(dest_port, Proxy), 443),
  ?assertEqual(maps:get(src_port, Proxy), 444),
  ?assertEqual(maps:get(inet, Proxy), "TCP4"),
  ?assertEqual(maps:get(vsn, Proxy), "2").

no_proxy_test() ->
  {ok, Map} = haproxy_protocol:parse(<<"GET / HTTP/1.1\r\n">>),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r\n">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), undefined),
  ?assertEqual(maps:get(src_address, Proxy), undefined),
  ?assertEqual(maps:get(dest_port, Proxy), undefined),
  ?assertEqual(maps:get(src_port, Proxy), undefined),
  ?assertEqual(maps:get(inet, Proxy), undefined),
  ?assertEqual(maps:get(vsn, Proxy), undefined).
