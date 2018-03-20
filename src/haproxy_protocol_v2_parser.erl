-module(haproxy_protocol_v2_parser).

-include("proxy.hrl").

-export([parse/1]).

parse(<<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 17,
  _Len:2/binary, Rest/binary>>) -> parse_ipv4("TCP4", Rest);

parse(<<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 18,
  _Len:2/binary, Rest/binary>>) -> parse_ipv4("UDP4", Rest);

parse(<<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 33,
  _Len:2/binary, Rest/binary>>) -> parse_ipv6("TCP6", Rest);

parse(<<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 34,
  _Len:2/binary, Rest/binary>>) -> parse_ipv6("UDP6", Rest);

parse(<<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 49,
  _Len:2/binary, Rest/binary>>) -> parse_unix(Rest);

parse(<<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 50,
  _Len:2/binary, Rest/binary>>) -> parse_unix(Rest);

parse(<<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 0,
  Len:2/binary, Rest/binary>>) -> unspec(Rest, uint16(Len));

parse(<<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, _Proto:1/binary,
  Len:2/binary, Rest/binary>>) -> unspec(Rest, uint16(Len));

parse(Buffer) ->
  {error, #{
    body => Buffer,
    header => #proxy{},
    message => "Does not match V2 of proxy protocol"
  }}.

parse_ipv4(Inet, <<SrcAddr:4/binary, DestAddr:4/binary,
  SrcPort:2/binary, DestPort:2/binary, Rest/binary>>) ->

  {ok, #{
    body => Rest,
    header => build_proxy(
      ipv4(SrcAddr),
      ipv4(DestAddr),
      uint16(SrcPort),
      uint16(DestPort),
      Inet
    )
  }}.

parse_ipv6(Inet, <<SrcAddr:16/binary, DestAddr:16/binary,
  SrcPort:2/binary, DestPort:2/binary, Rest/binary>>) ->

  {ok, #{
    body => Rest,
    header => build_proxy(
      ipv6(SrcAddr),
      ipv6(DestAddr),
      uint16(SrcPort),
      uint16(DestPort),
      Inet
    )
  }}.

parse_unix(<<SrcAddr:108/binary, DestAddr:108/binary, Rest/binary>>) ->
  {ok, #{
    body => Rest,
    header => build_proxy(
      socket(SrcAddr),
      socket(DestAddr),
      undefined,
      undefined,
      "AF_UNIX"
    )
  }}.

unspec(Buffer, Size) ->
  <<_Skip:(Size)/binary, Rest/binary>> = Buffer,
  {ok, #{
    body => Rest,
    header => #proxy{inet = "UNKNOWN", vsn = "2"}
  }}.

ipv4(<<One, Two, Three, Four>>) -> {One, Two, Three, Four}.

ipv6(<<One:2/binary, Two:2/binary, Three:2/binary, Four:2/binary,
  Five:2/binary, Six:2/binary, Seven:2/binary, Eight:2/binary>>) ->
  {uint16(One), uint16(Two), uint16(Three), uint16(Four),
    uint16(Five), uint16(Six), uint16(Seven), uint16(Eight)}.

uint16(<<One, Two>>) -> One * 256 + Two.

socket(Socket = <<0, _Rest/binary>>) -> Socket;
socket(Pathname) -> parse_socket(Pathname, <<>>).

parse_socket(<<>>, Acc) -> Acc;
parse_socket(<<0, _Rest/binary>>, Acc) -> Acc;
parse_socket(<<Char:1/binary, Rest/binary>>, Acc) ->
  parse_socket(Rest, <<Acc/binary, Char/binary>>).

build_proxy(SrcAddr, DestAddr, SrcPort, DestPort, Inet) ->
  #proxy{
    dest_address = DestAddr,
    dest_port = DestPort,
    inet = Inet,
    src_address = SrcAddr,
    src_port = SrcPort,
    vsn = "2"
  }.
