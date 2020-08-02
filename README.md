IPRI MPC
===
---
# C++

### Install

The library requires boost to run. After cloning the repo, run

`bash boost.get`

to build boost from source. Currently, it is necessary to keep the boost library where it is placed by this script.

Once boost is installed, run

`make`

from the top directory to build the library.

### Demo

To run the C++ demo, you'll need a terminal open for the server as well as each client. For the server terminal, run the command
`bin/demo/ahe/loan-sum-demo 0 [number of clients]`
e.g.
`bin/demo/ahe/loan-sum-demo 0 3` for a demo with three clients.

To run a client, just give the binary the client number. All client numbers must be unique and in the range [0, num clients].
`bin/demo/ahe/loan-sum-demo 1` for client 1.

-----

# Python

You will need all the C++ components to run the python demo.

### Install

To run the python demo, you nee the `bottle` and `gevent-websocket` python libraries.

`pip3 install bottle`

`pip3 install gevent-websocket`


### Demo

As in the C++ demo, all programs must be run from the top directory.

The python demo is currently in very early stages. You need to run a client machine and a server machine, then connect to the client machine through your browser.
`python3 py-demo/server.py`
The server will listen at `localhost:8080`.

The client can be launched by going into `py-demo` and then running
`python3 client.py`
The client will listen at `localhost:9030` and will server `index.html` to the browser.

To run multiple clients, you need to run multiple instances of `client.py`, each on a different port. To run a client on `localhost:9040`, run the command

`python3 py-demo/client.py 9040`

The demo should be able to handle an arbitrary number of clients.
