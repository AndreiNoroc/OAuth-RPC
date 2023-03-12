RPC = rpcgen
CC = g++
CFLAGS += -std=c++14 -g -I/usr/include/tirpc
LDLIBS += -lnsl -ltirpc
PROGRAM = oauth
SRC_SERVER = $(PROGRAM)_svc.h $(PROGRAM)_xdr.c
SRC_CLIENT = $(PROGRAM)_clnt.c $(PROGRAM)_xdr.c

.PHONY: build clean

build: server client

server: $(SRC_SERVER) $(PROGRAM)_rpc_server.cpp
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

client: $(SRC_CLIENT) $(PROGRAM)_rpc_client.cpp
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(PROGRAM)_xdr.c $(PROGRAM)_clnt.c $(PROGRAM)_svc.h: $(PROGRAM).x
	$(RPC) -m > $(PROGRAM)_svc.h $^
	$(RPC) -l > $(PROGRAM)_clnt.c $^
	$(RPC) -h > $(PROGRAM).h $^
	$(RPC) -c > $(PROGRAM)_xdr.c $^

clean:
	rm -f client server $(PROGRAM).h $(PROGRAM)_svc.h $(SRC_SERVER) $(SRC_CLIENT) *.out
