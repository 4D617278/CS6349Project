---- MODULE client ----
EXTENDS Naturals, Sequences, TLC, FiniteSets

CONSTANT NUM_CLIENTS
CONSTANT MAX_KEYS
CONSTANT MAX_IPS
ASSUME NUM_CLIENTS >= 1
ASSUME MAX_KEYS >= 1
ASSUME MAX_IPS >= 1

Range(seq) == {seq[key]: key \in DOMAIN seq}
Unique(seq) == 
    \A e1, e2 \in DOMAIN seq:
        e1 # e2 => seq[e1] # seq[e2]

(* --algorithm client
variables
 idle = TRUE;
 Ips = 1..MAX_IPS;
 Keys = 0..MAX_KEYS;
 ip \in Ips;
 clientIps = <<1, 2, 3>>;
 creds = "";
 key = 0;
 peerIp = 0;

define
  TypeInvariant ==
    /\ idle \in BOOLEAN
    /\ ip \in Ips
    /\ clientIps \in [1..NUM_CLIENTS -> Ips]
    /\ key \in Keys
    /\ peerIp \in Ips \union {0}
  
  NoLoopback == ip # peerIp

  UniqueIps == Unique(clientIps)

  SessionChange ==
    [][peerIp # peerIp' => idle = TRUE \/ peerIp' = 0]_peerIp

  IdleIsNoSession == 
    /\ idle = TRUE => peerIp = 0

  BusyIsSession == 
    /\ idle = FALSE => peerIp # 0

  NoSessionChange == 
    [][idle = FALSE => peerIp' = peerIp \/ peerIp' = 0]_peerIp

  IdleBeforeSession == 
    [][peerIp = 0 /\ peerIp # peerIp' => idle = TRUE]_peerIp
end define;

begin
  getList:
    with randSeq \in [1..NUM_CLIENTS -> Ips]; do
        if Unique(randSeq) then
            clientIps := randSeq;
        end if;
    end with;

  getKey:
    print <<"Start: ", peerIp, idle>>;
    idle := FALSE;
    with randIp \in Range(clientIps) \ {ip}; do
        peerIp := randIp;
    end with;
    with randKey \in Keys; do
        key := randKey;
    end with;
    print <<"End: ", peerIp, idle>>;
    (* goto getKey; *)

  startSession:
    if idle = TRUE then
        idle := FALSE;
        with randIp \in Range(clientIps) \ {ip}; do
            peerIp := randIp;
        end with;
    end if;
    (* goto getKey; *)

  endSession:
    if idle = FALSE then
        idle := TRUE;
        peerIp := 0;
    end if
end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "cff4f88d" /\ chksum(tla) = "7dec6117")
VARIABLES idle, Ips, Keys, ip, clientIps, creds, key, peerIp, pc

(* define statement *)
TypeInvariant ==
  /\ idle \in BOOLEAN
  /\ ip \in Ips
  /\ clientIps \in [1..NUM_CLIENTS -> Ips]
  /\ key \in Keys
  /\ peerIp \in Ips \union {0}

NoLoopback == ip # peerIp

UniqueIps == Unique(clientIps)

SessionChange ==
  [][peerIp # peerIp' => idle = TRUE \/ peerIp' = 0]_peerIp

IdleIsNoSession ==
  /\ idle = TRUE => peerIp = 0

BusyIsSession ==
  /\ idle = FALSE => peerIp # 0

NoSessionChange ==
  [][idle = FALSE => peerIp' = peerIp \/ peerIp' = 0]_peerIp

IdleBeforeSession ==
  [][peerIp = 0 /\ peerIp # peerIp' => idle = TRUE]_peerIp


vars == << idle, Ips, Keys, ip, clientIps, creds, key, peerIp, pc >>

Init == (* Global variables *)
        /\ idle = TRUE
        /\ Ips = 1..MAX_IPS
        /\ Keys = 0..MAX_KEYS
        /\ ip \in Ips
        /\ clientIps = <<1, 2, 3>>
        /\ creds = ""
        /\ key = 0
        /\ peerIp = 0
        /\ pc = "getList"

getList == /\ pc = "getList"
           /\ \E randSeq \in [1..NUM_CLIENTS -> Ips]:
                IF Unique(randSeq)
                   THEN /\ clientIps' = randSeq
                   ELSE /\ TRUE
                        /\ UNCHANGED clientIps
           /\ pc' = "getKey"
           /\ UNCHANGED << idle, Ips, Keys, ip, creds, key, peerIp >>

getKey == /\ pc = "getKey"
          /\ PrintT(<<"Start: ", peerIp, idle>>)
          /\ idle' = FALSE
          /\ \E randIp \in Range(clientIps) \ {ip}:
               peerIp' = randIp
          /\ \E randKey \in Keys:
               key' = randKey
          /\ PrintT(<<"End: ", peerIp', idle'>>)
          /\ pc' = "startSession"
          /\ UNCHANGED << Ips, Keys, ip, clientIps, creds >>

startSession == /\ pc = "startSession"
                /\ IF idle = TRUE
                      THEN /\ idle' = FALSE
                           /\ \E randIp \in Range(clientIps) \ {ip}:
                                peerIp' = randIp
                      ELSE /\ TRUE
                           /\ UNCHANGED << idle, peerIp >>
                /\ pc' = "endSession"
                /\ UNCHANGED << Ips, Keys, ip, clientIps, creds, key >>

endSession == /\ pc = "endSession"
              /\ IF idle = FALSE
                    THEN /\ idle' = TRUE
                         /\ peerIp' = 0
                    ELSE /\ TRUE
                         /\ UNCHANGED << idle, peerIp >>
              /\ pc' = "Done"
              /\ UNCHANGED << Ips, Keys, ip, clientIps, creds, key >>

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == pc = "Done" /\ UNCHANGED vars

Next == getList \/ getKey \/ startSession \/ endSession
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(pc = "Done")

\* END TRANSLATION 
====
