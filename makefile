CC = g++
CFLAGS  = -g
SERVER = server
CLIENT = client

all: 
	$(CC) $(CFLAGS) -o $(SERVER) -lcrypto $(SERVER).cpp && $(CC) $(CFLAGS) -o $(CLIENT) -lcrypto $(CLIENT).cpp

client:	all
	./$(CLIENT) $(ARGS) $(CLIENT).conf

server: all 
	./${SERVER} $(ARGS) $(SERVER).conf

clean:
	$(RM) $(SERVER) $(CLIENT) -r db




# all: 
# 	$(CC) $(CFLAGS) -o $(SERVER) $(SERVER).cpp
# #	$(CC) $(CFLAGS) -o $(CLIENT) $(CLIENT).cpp
	
# server:	${SERVER}
# 	./${SERVER} ${ARGS}

# client: ${CLIENT}
# 	./${CLIENT} ${ARGS}

# clean:
# 	$(RM) $(CLIENT) && $(RM) $(SERVER)
