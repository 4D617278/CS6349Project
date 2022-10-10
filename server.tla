---- MODULE server ----
EXTENDS Naturals, Sequences, TLC

CONSTANT MAX_KEY
CONSTANT NUM_CLIENTS
CONSTANT NUM_SERVERS
ASSUME NUM_SERVERS >= 1
ASSUME NUM_CLIENTS >= 1

(* --algorithm server
variables
 id \in 1..NUM_SERVERS;
 clientList \in [1..NUM_CLIENTS -> BOOLEAN];
 clientIps \in [1..NUM_CLIENTS -> ips];
 clientCreds \in [1..NUM_CLIENTS -> 1..5];

define
  TypeInvariant ==
    /\ id \in 1..NUM_SERVERS;
    /\ clientList \in [1..NUM_CLIENTS -> BOOLEAN]
    /\ clientIps \in [1..NUM_CLIENTS -> ips]
end define;

begin
  setList:
    with randList \in [1..NUM_CLIENTS -> BOOLEAN]; do
        clientList := randList;
    end with;

  setKey:
    with randKey \in 1..MAX_KEY; do
        key := randKey;
    end with;
end algorithm; *)
====
