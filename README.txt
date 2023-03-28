MAKEFILE COMMANDS:
make (or make all):
compiles both server.cpp and client.cpp

make client
compiles and runs client

make server
compiles and runs server

make clean
removes all executables, as well as db file folder

TO USE THIS PROGRAM:
The user must start the server program, followed by the client program to be
able to connect properly. If the user wishes for interdomain interactions, the
server.conf file must be updated accordingly. There must be at least 1 
remote domain specified in this file for the program to work properly.

When running on the zone server, make sure 
the src file folder is in all destinations. On any destination where server is
desires use "make server" command to start the server. Once the server is started,
on the other destination(s), use the "make client" command to start the client. Once
both the client and server are started, you can start sending messages from the
client to the server.

IF MAKE COMMANDS ARE NOT WORKING:
to compile server: 
g++ server.cpp -o server -lcrypto && ./server

to compile client:
g++ client.cpp -o client -lcrypto && ./client

NOTE: Once both client and server are running, the server will output the correct
hostname to use for the HELO <server-hostname> to function properly which will allow
the client to enter the email sequence.
