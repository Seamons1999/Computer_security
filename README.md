### Run the server and the clients
- open a terminal
- type "python server.py" to start the server (you will need the certification files)
- In another terminal, type "python client.py 1" to test client 1
- Likewise, you can type "python client.py 2" to test client 2 (there are 6 clients in total)
- To change the clients, just update the .json files

### To encrypt the log files
- By default, when running server.py, the app.log file displays the operations in the app
- If you want an encrypted app.log file, just run encrypted.server.py instead
- If you want to read the encrypted log, run decrypt_logs.py (you will need the secret.key file)
