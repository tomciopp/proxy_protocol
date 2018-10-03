-module(haproxy_protocol).

-export([parse/1]).

parse(Packet = <<"\r\n\r\n\0\r\nQUIT\n", _Rest/binary>>) ->
  haproxy_protocol_v2_parser:parse(Packet);

parse(Packet = <<"PROXY TCP4 ", _Rest/binary>>) ->
  haproxy_protocol_v1_parser:parse(Packet);

parse(Packet = <<"PROXY TCP6 ", _Rest/binary>>) ->
  haproxy_protocol_v1_parser:parse(Packet);

parse(Packet = <<"PROXY UNKNOWN ", _Rest/binary>>) ->
  haproxy_protocol_v1_parser:parse(Packet);

parse(Packet = <<"PROXY UNKNOWN\r\n", _Rest/binary>>) ->
  haproxy_protocol_v1_parser:parse(Packet);

parse(Packet) ->
  {ok, #{
    body => Packet,
    header => #{
      dest_address => undefined,
      dest_port => undefined,
      inet => undefined,
      src_address => undefined,
      src_port => undefined,
      vsn => undefined
    }
  }}.
