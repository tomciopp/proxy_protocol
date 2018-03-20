-module(haproxy_protocol_v1_parser).

-export([parse/1]).

parse(Packet) -> inet(Packet, default_header()).

default_header() ->
  #{
    dest_address => undefined,
    dest_port => undefined,
    inet => undefined,
    src_address => undefined,
    src_port => undefined,
    vsn => "1"
  }.

inet(<<"PROXY TCP4 ", Rest/binary>>, Proxy) ->
  src_address(Rest, maps:put(inet, "TCP4", Proxy));

inet(<<"PROXY TCP6 ", Rest/binary>>, Proxy) ->
  src_address(Rest, maps:put(inet, "TCP6", Proxy));

inet(<<"PROXY UNKNOWN", Rest/binary>>, Proxy) ->
  {ok, #{
    body => drop_line(Rest),
    header => maps:put(inet, "UNKNOWN", Proxy)
  }}.

src_address(Buffer, Proxy) ->
  case find_ip(Buffer, Proxy) of
    {ok, Address, Rest} ->
      dest_address(Rest, maps:put(src_address, Address, Proxy));
    {error, Message} ->
      {error, #{body => Buffer, header => Proxy, message => Message}}
  end.

dest_address(Buffer, Proxy) ->
  case find_ip(Buffer, Proxy) of
    {ok, Address, Rest} ->
      src_port(Rest, maps:put(dest_address, Address, Proxy));
    {error, Message} ->
      {error, #{body => Buffer, header => Proxy, message => Message}}
  end.

src_port(Buffer, Proxy) ->
  try find_port(Buffer) of
    {ok, Port, Rest} ->
      dest_port(Rest, maps:put(src_port, Port, Proxy));
    {error, Message} ->
      {error, #{body => Buffer, header => Proxy, message => Message}}
  catch
    error:badarg ->
      {error, #{
        body => Buffer,
        header => Proxy,
        message => "There was an error parsing the src_port"
      }}
  end.

dest_port(Buffer, Proxy) ->
  try find_port(Buffer) of
    {ok, Port, Rest} ->
      {ok, #{body => Rest, header => maps:put(dest_port, Port, Proxy)}};
    {error, Message} ->
      {error, #{body => Buffer, header => Proxy, message => Message}}
  catch
    error:badarg ->
      {error, #{
        body => Buffer,
        header => Proxy,
        message => "There was an error parsing the dest_port"
      }}
  end.

find_ip(Buffer, #{inet := "TCP4"}) -> ipv4(Buffer);
find_ip(Buffer, #{inet := "TCP6"}) -> ipv6(Buffer).

% IPv4 can be in the range of 0.0.0.0 - 255.255.255.255
ipv4(<<Addr:7/binary,  32, Rest/binary>>) -> valid_ip(Addr, Rest);
ipv4(<<Addr:8/binary,  32, Rest/binary>>) -> valid_ip(Addr, Rest);
ipv4(<<Addr:9/binary,  32, Rest/binary>>) -> valid_ip(Addr, Rest);
ipv4(<<Addr:10/binary, 32, Rest/binary>>) -> valid_ip(Addr, Rest);
ipv4(<<Addr:11/binary, 32, Rest/binary>>) -> valid_ip(Addr, Rest);
ipv4(<<Addr:12/binary, 32, Rest/binary>>) -> valid_ip(Addr, Rest);
ipv4(<<Addr:13/binary, 32, Rest/binary>>) -> valid_ip(Addr, Rest);
ipv4(<<Addr:14/binary, 32, Rest/binary>>) -> valid_ip(Addr, Rest);
ipv4(<<Addr:15/binary, 32, Rest/binary>>) -> valid_ip(Addr, Rest);
ipv4(_) -> {error, "Buffer does not match ipv4 format"}.

% IPv6 format is 8 groups of 4 digit hex chars separated by colon
% ex: 2001:0db8:0000:0042:0000:8a2e:0370:7334
ipv6(<<Addr:39/binary, 32, Rest/binary>>) -> valid_ip(Addr, Rest);
ipv6(_) -> {error, "Buffer does not match ipv6 format"}.

valid_ip(Addr, Buffer) ->
  case inet:parse_address(binary:bin_to_list(Addr)) of
    {ok, Ip} -> {ok, Ip, Buffer};
    {error, _} -> {error, "Ip address is invalid"}
  end.

% Ports can be in the range of 0..65535
find_port(<<Port:1/binary, 32, Rest/binary>>) ->
  valid_port(binary_to_integer(Port), Rest);

find_port(<<Port:2/binary, 32, Rest/binary>>) ->
  valid_port(binary_to_integer(Port), Rest);

find_port(<<Port:3/binary, 32, Rest/binary>>) ->
  valid_port(binary_to_integer(Port), Rest);

find_port(<<Port:4/binary, 32, Rest/binary>>) ->
  valid_port(binary_to_integer(Port), Rest);

find_port(<<Port:5/binary, 32, Rest/binary>>) ->
  valid_port(binary_to_integer(Port), Rest);

find_port(<<Port:1/binary, 13, 10, Rest/binary>>) ->
  valid_port(binary_to_integer(Port), Rest);

find_port(<<Port:2/binary, 13, 10, Rest/binary>>) ->
  valid_port(binary_to_integer(Port), Rest);

find_port(<<Port:3/binary, 13, 10, Rest/binary>>) ->
  valid_port(binary_to_integer(Port), Rest);

find_port(<<Port:4/binary, 13, 10, Rest/binary>>) ->
  valid_port(binary_to_integer(Port), Rest);

find_port(<<Port:5/binary, 13, 10, Rest/binary>>) ->
  valid_port(binary_to_integer(Port), Rest);

find_port(_) -> {error, "Buffer does not match port format"}.

valid_port(Port, Buffer) ->
  if
    (Port >= 0) and (Port =< 65535) -> {ok, Port, Buffer};
    true -> {error, "Port must be between 0 and 65535"}
  end.

drop_line(<<13, 10, Rest/binary>>) -> Rest;
drop_line(<<_Byte:1/binary, Rest/binary>>) -> drop_line(Rest).
