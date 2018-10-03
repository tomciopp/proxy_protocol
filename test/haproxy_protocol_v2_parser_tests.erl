-module(haproxy_protocol_v2_parser_tests).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").

tcp4_success_test() ->
  Signature = <<13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 17>>,
  Length = <<0, 12>>,
  SrcAddress = <<127, 0, 0, 1>>,
  DestAddress = <<192, 168, 0, 1>>,
  SrcPort = <<1, 188>>,
  DestPort = <<1, 187>>,
  Request = <<"GET / HTTP/1.1\r\n">>,
  Packet = <<Signature/binary, Length/binary, SrcAddress/binary,
    DestAddress/binary, SrcPort/binary, DestPort/binary, Request/binary>>,

  {ok, Map} = haproxy_protocol_v2_parser:parse(Packet),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r\n">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), {192, 168, 0, 1}),
  ?assertEqual(maps:get(src_address, Proxy), {127, 0, 0, 1}),
  ?assertEqual(maps:get(dest_port, Proxy), 443),
  ?assertEqual(maps:get(src_port, Proxy), 444),
  ?assertEqual(maps:get(inet, Proxy), "TCP4"),
  ?assertEqual(maps:get(vsn, Proxy), "2").

udp4_success_test() ->
  Signature = <<13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 18>>,
  Length = <<0, 12>>,
  SrcAddress = <<127, 0, 0, 1>>,
  DestAddress = <<192, 168, 0, 1>>,
  SrcPort = <<1, 188>>,
  DestPort = <<1, 187>>,
  Request = <<"GET / HTTP/1.1\r\n">>,
  Packet = <<Signature/binary, Length/binary, SrcAddress/binary,
    DestAddress/binary, SrcPort/binary, DestPort/binary, Request/binary>>,

  {ok, Map} = haproxy_protocol_v2_parser:parse(Packet),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r\n">>, maps:get(body, Map)),
  ?assertEqual(maps:get(dest_address, Proxy), {192, 168, 0, 1}),
  ?assertEqual(maps:get(src_address, Proxy), {127, 0, 0, 1}),
  ?assertEqual(maps:get(dest_port, Proxy), 443),
  ?assertEqual(maps:get(src_port, Proxy), 444),
  ?assertEqual(maps:get(inet, Proxy), "UDP4"),
  ?assertEqual(maps:get(vsn, Proxy), "2").

tcp6_success_test() ->
  Signature = <<13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 33>>,
  Length = <<0, 12>>,
  SrcAddress = <<21, 156, 16, 144, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
  DestAddress = <<32, 1, 13, 184, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
  SrcPort = <<1, 188>>,
  DestPort = <<1, 187>>,
  Request = <<"GET / HTTP/1.1\r\n">>,
  Packet = <<Signature/binary, Length/binary, SrcAddress/binary,
    DestAddress/binary, SrcPort/binary, DestPort/binary, Request/binary>>,

  {ok, Map} = haproxy_protocol_v2_parser:parse(Packet),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r\n">>, maps:get(body, Map)),
  ?assertEqual(maps:get(src_address, Proxy), {5532, 4240, 1, 0, 0, 0, 0, 0}),
  ?assertEqual(maps:get(dest_address, Proxy), {8193, 3512, 1, 0, 0, 0, 0, 0}),
  ?assertEqual(maps:get(src_port, Proxy), 444),
  ?assertEqual(maps:get(dest_port, Proxy), 443),
  ?assertEqual(maps:get(inet, Proxy), "TCP6"),
  ?assertEqual(maps:get(vsn, Proxy), "2").

udp6_success_test() ->
  Signature = <<13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 34>>,
  Length = <<0, 12>>,
  SrcAddress = <<21, 156, 16, 144, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
  DestAddress = <<32, 1, 13, 184, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
  SrcPort = <<1, 188>>,
  DestPort = <<1, 187>>,
  Request = <<"GET / HTTP/1.1\r\n">>,
  Packet = <<Signature/binary, Length/binary, SrcAddress/binary,
    DestAddress/binary, SrcPort/binary, DestPort/binary, Request/binary>>,

  {ok, Map} = haproxy_protocol_v2_parser:parse(Packet),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r\n">>, maps:get(body, Map)),
  ?assertEqual(maps:get(src_address, Proxy), {5532, 4240, 1, 0, 0, 0, 0, 0}),
  ?assertEqual(maps:get(dest_address, Proxy), {8193, 3512, 1, 0, 0, 0, 0, 0}),
  ?assertEqual(maps:get(src_port, Proxy), 444),
  ?assertEqual(maps:get(dest_port, Proxy), 443),
  ?assertEqual(maps:get(inet, Proxy), "UDP6"),
  ?assertEqual(maps:get(vsn, Proxy), "2").

stream_success_test() ->
  Signature = <<13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 49>>,
  Length = <<0, 12>>,
  Path = <<47, 118, 97, 114, 47, 112, 103, 115, 113, 108, 95, 115, 111, 99, 107, 0>>,
  Padding = list_to_binary(string:copies("0", 92)),
  SrcAddress = <<Path/binary, Padding/binary>>,
  DestAddress = <<Path/binary, Padding/binary>>,
  Request = <<"GET / HTTP/1.1\r\n">>,
  Packet = <<Signature/binary, Length/binary, SrcAddress/binary,
    DestAddress/binary, Request/binary>>,

  {ok, Map} = haproxy_protocol_v2_parser:parse(Packet),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r\n">>, maps:get(body, Map)),
  ?assertEqual(maps:get(src_address, Proxy), <<"/var/pgsql_sock">>),
  ?assertEqual(maps:get(dest_address, Proxy), <<"/var/pgsql_sock">>),
  ?assertEqual(maps:get(src_port, Proxy), undefined),
  ?assertEqual(maps:get(dest_port, Proxy), undefined),
  ?assertEqual(maps:get(inet, Proxy), "AF_UNIX"),
  ?assertEqual(maps:get(vsn, Proxy), "2").

dgram_success_test() ->
  Signature = <<13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 50>>,
  Length = <<0, 12>>,
  Path = <<47, 118, 97, 114, 47, 112, 103, 115, 113, 108, 95, 115, 111, 99, 107, 0>>,
  Padding = list_to_binary(string:copies("0", 92)),
  SrcAddress = <<Path/binary, Padding/binary>>,
  DestAddress = <<Path/binary, Padding/binary>>,
  Request = <<"GET / HTTP/1.1\r\n">>,
  Packet = <<Signature/binary, Length/binary, SrcAddress/binary,
    DestAddress/binary, Request/binary>>,

  {ok, Map} = haproxy_protocol_v2_parser:parse(Packet),
  Proxy = maps:get(header, Map),

  ?assertEqual(<<"GET / HTTP/1.1\r\n">>, maps:get(body, Map)),
  ?assertEqual(maps:get(src_address, Proxy), <<"/var/pgsql_sock">>),
  ?assertEqual(maps:get(dest_address, Proxy), <<"/var/pgsql_sock">>),
  ?assertEqual(maps:get(src_port, Proxy), undefined),
  ?assertEqual(maps:get(dest_port, Proxy), undefined),
  ?assertEqual(maps:get(inet, Proxy), "AF_UNIX"),
  ?assertEqual(maps:get(vsn, Proxy), "2").
