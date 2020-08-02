import sys
import subprocess
from bottle import route, run, debug, template, request, BaseRequest, abort, Bottle, static_file, url
import json
import urllib.request
import urllib.parse
from threading import Thread
from time import sleep

BaseRequest.MEMFILE_MAX = 2048 * 8192  # (or whatever you want)


################################################################################
## DATA
################################################################################
SERVER_ADDRESS = 'http://localhost:8080/'
NUM_LIMBS = 3

CLIENT_PORT = 9030
if (len(sys.argv) > 1):
    CLIENT_PORT = int(sys.argv[1])
CLIENT_ADDRESS = 'localhost'

CLIENT_NUMBER = 0
NUM_CLIENTS = 0
SEED_HALVES = None

SECRET_KEY = []
PUBLIC_KEY = []
SHARED_PK = None

FILE_NAMES = ["client1_pen_data.csv", "client2_pen_data.csv", "client3_pen_data.csv"];
CIPHERTEXT = []

ORIGLENGTH = 0  ## Used to truncate the decryption output to only the relevent data
ENCRYPTED_RESULT = []
DECRYPTION_SHARES = []
RESULTS = []

WEBSOCK = None  ## Websocket object where we can push messages to the client
## NOTE: The flow of data through the websocket should only by from the application
##         to the browser. The browser should use the API to

################################################################################
## SERVICES
################################################################################

app = Bottle()  ## This is the Bottle object that will be passed to the web socket handler


@app.route('/websocket')
def handle_websocket():
    global WEBSOCK
    WEBSOCK = request.environ.get('wsgi.websocket')
    if not WEBSOCK:
        abort(400, 'Expected websocket request.')
    print("WebSocket connected")
    # Thread(target=waitForClose).start()
    while True:
        try:
            message = WEBSOCK.receive()
            if message == "CLOSE":
                print("WEBSOCKET is CLOSED")
                return
            sleep(1)
        except WebSocketError:
            break

@app.route('/register')
def register():
    print('In register...')
    global CLIENT_NUMBER
    if (CLIENT_NUMBER != 0):
        global SHARED_PK
        if SHARED_PK:
            global WEBSOCK
            keyPush = {'msg': "PUBKEY", 'numClients': str(NUM_CLIENTS), 'pka': SHARED_PK, 'pkb': SHARED_PK}
            WEBSOCK.send(json.dumps(keyPush))
            global ENCRYPTED_RESULT
            if len(ENCRYPTED_RESULT) > 0:
                sendEncResult()
                global RESULTS
                if len(RESULTS) > 0:
                    sendResultsToClient()
            else:
                startNewComp()
        return json.dumps({'result': str(CLIENT_NUMBER)})

    response = urllib.request.urlopen(SERVER_ADDRESS + 'register')
    print("Received response from server")
    jsonResult = json.loads(response.read().decode('utf-8'))
    print("Registration result ", jsonResult)

    CLIENT_NUMBER = int(jsonResult['clientNum'])

    ## Generate key with seed
    keyGenArgs = [jsonResult['seedFirstHalf'], jsonResult['seedSecondHalf']]
    keyString = subprocess.check_output(["bash", "scripts/keyGen.bash"] + keyGenArgs).decode('utf-8')
    keyElems = keyString.split('\n')
    # print(keyElems)
    keyElems = keyElems[:len(keyElems)-1]
    global NUM_LIMBS
    # print(keyElems)
    assert(len(keyElems) == NUM_LIMBS*3)

    global SECRET_KEY
    global PUBLIC_KEY
    for i in range(NUM_LIMBS):
        SECRET_KEY.append(keyElems[i])
    PUBLIC_KEY.append([])
    for i in range(NUM_LIMBS, 2*NUM_LIMBS):
        PUBLIC_KEY[0].append(keyElems[i])
    PUBLIC_KEY.append([])
    for i in range(2*NUM_LIMBS, 3*NUM_LIMBS):
        PUBLIC_KEY[1].append(keyElems[i])

    # PUBLIC_KEY = [keyElems[1], keyElems[2]]

    ## Post public key to the server
    toEncodePK = {'clientNum': str(CLIENT_NUMBER), 'pka': ';'.join(PUBLIC_KEY[0]), 'pkb': ';'.join(PUBLIC_KEY[1])}
    # print("Sending pk: ", toEncodePK)
    urlPK = urllib.parse.urlencode(toEncodePK).encode('ascii')
    urllib.request.urlopen(SERVER_ADDRESS + 'postPK', urlPK)

    return json.dumps({'result': str(CLIENT_NUMBER)})


@app.route('/keyGen')
def readyUp():
    print("In readyup...")

    global SHARED_PK
    if SHARED_PK:
        print("Shared key already generated")
        global NUM_CLIENTS
        keyPush = {'msg': "PUBKEY", 'numClients': str(NUM_CLIENTS), 'pka': SHARED_PK, 'pkb': SHARED_PK}
        WEBSOCK.send(json.dumps(keyPush))
        return

    global CLIENT_NUMBER
    global CLIENT_ADDRESS
    global CLIENT_PORT
    readyUpArgs = {'clientNum': str(CLIENT_NUMBER), 'address': 'http://' + CLIENT_ADDRESS + ':' + str(CLIENT_PORT) + '/'}
    urlReadyUp = urllib.parse.urlencode(readyUpArgs).encode('ascii')
    # urllib.request.urlopen(SERVER_ADDRESS + "keyGen", urlReadyUp)
    Thread(target=urllib.request.urlopen, args=[SERVER_ADDRESS + 'keyGen', urlReadyUp]).start()

    print("Requested shared keygen from server")


@app.route('/receivePublicKey', method=['POST'])
def receivePublicKey():
    global SHARED_PK
    if SHARED_PK:
        return

    pka = request.params.get('mpPKa', 0, type=str)
    pkb = request.params.get('mpPKb', 0, type=str)
    pka = pka.split(';')
    pkb = pkb.split(';')
    for i in range(len(pka)):
        pka[i] = pka[i][:len(pka[i])-1]
        pkb[i] = pkb[i][:len(pkb[i])-1]
    SHARED_PK = [pka, pkb]
    # print("Received shared key: ", SHARED_PK)

    global NUM_CLIENTS
    NUM_CLIENTS = request.params.get('numClients', 0, type=int)
    print("Received shared key generated from " + str(NUM_CLIENTS) + " client keys")

    global WEBSOCK
    keyPush = {'msg': "PUBKEY", 'numClients': str(NUM_CLIENTS), 'pka': SHARED_PK, 'pkb': SHARED_PK}
    WEBSOCK.send(json.dumps(keyPush))


@app.route('/encryptVector')
def encryptVector():
    global SHARED_PK
    if not SHARED_PK:
        return

    # print("We have shared pk: ", SHARED_PK)

    global CIPHERTEXT
    toEnc = request.params.get('data', type=str)
    toSquare = toEnc.split(" ")
    squareString = ""
    for i in range(len(toSquare)):
        squareString += str(int(toSquare[i])**2)
        if (i != len(toSquare)-1):
            squareString += " "

    # print(toEnc)
    global ORIGLENGTH
    ORIGLENGTH = len(toEnc.split(" "))
    ciphertext = subprocess.check_output(["bash", "scripts/encryptVec.bash", toEnc] + SHARED_PK[0] + SHARED_PK[1]).decode('utf-8')
    ciphertext = ciphertext.split('\n')
    # print(ciphertext)
    global NUM_LIMBS
    assert(len(ciphertext) == 4*NUM_LIMBS + 1)
    CIPHERTEXT = []
    ctRegA = []
    ctRegB = []
    ctSqA = []
    ctSqB = []
    for i in range(NUM_LIMBS):
        ctRegA.append(ciphertext[i])
        ctRegB.append(ciphertext[i+NUM_LIMBS])
        ctSqA.append(ciphertext[i + 2*NUM_LIMBS])
        ctSqB.append(ciphertext[i + 3*NUM_LIMBS])
    # CIPHERTEXT.append([ciphertext[0], ciphertext[1]])
    # CIPHERTEXT.append([ciphertext[2], ciphertext[3]])
    CIPHERTEXT.append([ctRegA, ctRegB])
    CIPHERTEXT.append([ctSqA, ctSqB])
    # print("Loaded ciphertext: ", CIPHERTEXT)

    print("Returning encrypted data to client")
    return json.dumps({'cta': ciphertext[0], 'ctb': ciphertext[1]})


def sendEncResult():
    global WEBSOCK
    encResultPush = {'msg': 'ENCRESULT', 'cta': ENCRYPTED_RESULT[0][0], 'ctb': ENCRYPTED_RESULT[0][1]}
    WEBSOCK.send(json.dumps(encResultPush))
    return json.dumps({'result': 'False'})


@app.route('/sendData')
def sendData():
    global CIPHERTEXT
    if len(CIPHERTEXT) == 0:
        return  # json.dumps({'result': 'False'})

    global ENCRYPTED_RESULT
    if len(ENCRYPTED_RESULT) > 0:
        return sendEncResult()

    print("Sending ciphertext to server")
    global CLIENT_NUMBER
    postCtArgs = {'clientNum': str(CLIENT_NUMBER)}
    ctInd = 0
    for ct in CIPHERTEXT:
        ctaLabel = "cta" + str(ctInd)
        ctbLabel = "ctb" + str(ctInd)
        postCtArgs[ctaLabel] = ';'.join(ct[0])
        postCtArgs[ctbLabel] = ';'.join(ct[1])
        # postCtArgs[ctLabel] = {'cta': ct[0], 'ctb': ct[1]}
        ctInd += 1
    postCtArgs['numCts'] = str(ctInd)

    urlCtArgs = urllib.parse.urlencode(postCtArgs).encode('ascii')
    global SERVER_ADDRESS
    Thread(target=urllib.request.urlopen, args=[SERVER_ADDRESS + 'postCt', urlCtArgs]).start()

    return json.dumps({'result': 'True'})

@app.route('/postEncryptedResult', method=['POST'])
def receiveEnryptedResult():
    print("Receiving demo result")
    global ENCRYPTED_RESULT
    if len(ENCRYPTED_RESULT) > 0:
        return sendEncResult()


    numCts = request.params.get('numCts', 0, type=int)
    print("Received " + str(numCts) + " ciphertext from the server")
    for ctInd in range(numCts):
        ctaLabel = 'cta' + str(ctInd)
        ctbLabel = 'ctb' + str(ctInd)
        cta = request.params.get(ctaLabel, 0, type=str).split(';')
        ctb = request.params.get(ctbLabel, 0, type=str).split(';')
        ENCRYPTED_RESULT.append([cta, ctb])
        # return json.dumps({'result': 'True'})

    # print(len(ENCRYPTED_RESULT))
    # print("Enc result: ", ENCRYPTED_RESULT)

    return sendEncResult()

def sendResultsToClient():
    global RESULTS
    global WEBSOCK
    resultPush = {'msg': "RESULT", 'result': str(RESULTS[0]), 'hhi': str(RESULTS[1])}
    WEBSOCK.send(json.dumps(resultPush))

@app.route('/decrypt')
def genAndSendDecryptShare():
    print("Generating decryption shares")
    global DECRYPTION_SHARES
    if len(DECRYPTION_SHARES) > 0:
        global RESULTS
        if len(RESULTS) > 0:
            sendResultsToClient()
        return

    global NUM_CLIENTS
    global SECRET_KEY
    global ENCRYPTED_RESULT
    decArgs = [str(NUM_CLIENTS)] + SECRET_KEY
    for ct in ENCRYPTED_RESULT:
        decArgs.extend(ct[0])
        decArgs.extend(ct[1])

    # print("Dec args: ", decArgs)

    shares = subprocess.check_output(["bash", "scripts/decrypt.bash"] + decArgs).decode('utf-8')
    shares = shares.split('\n')
    shares = shares[:len(shares)-1]
    # print("Shares: ", shares)

    DECRYPTION_SHARES = [[], []]
    global NUM_LIMBS
    for i in range(NUM_LIMBS):
        DECRYPTION_SHARES[0].append(shares[i])
        DECRYPTION_SHARES[1].append(shares[i+NUM_LIMBS])

    global CLIENT_NUMBER
    sendSharesArgs = {'clientNum': CLIENT_NUMBER, 'numShares': len(ENCRYPTED_RESULT)}
    for s in range(len(DECRYPTION_SHARES)):
        shareLabel = "share" + str(s)
        sendSharesArgs[shareLabel] = ';'.join(DECRYPTION_SHARES[s])

    global SERVER_ADDRESS
    urlShares = urllib.parse.urlencode(sendSharesArgs).encode('ascii')
    # urllib.request.urlopen(SERVER_ADDRESS + 'decrypt', urlShares)
    Thread(target=urllib.request.urlopen, args=[SERVER_ADDRESS + 'decrypt', urlShares]).start()


def computeHHI():
    global RESULTS
    global NUM_CLIENTS
    avgVec = RESULTS[0]
    sum_sq = RESULTS[1]
    for i in range(len(avgVec)):
        sumTerms = NUM_CLIENTS*float(avgVec[i])
        if (sumTerms != 0):
            frac = float(sum_sq[i])/(sumTerms*sumTerms)
            # RESULTS[1][i] = frac
            clientFrac = float(1)/NUM_CLIENTS
            RESULTS[1][i] = (frac - clientFrac)/(1 - clientFrac)
        else:
            RESULTS[1][i] = 0

@app.route('/postResult', method=['POST'])
def receiveResult():
    print('Receiving computation results from server')
    global RESULTS
    if len(RESULTS) != 0:
        sendResultsToClient()
        return

    numResults = request.params.get('numResults', 0, type=int)
    global ORIGLENGTH
    global NUM_CLIENTS
    for r in range(numResults):
        resLabel = 'result' + str(r)
        rawResult = request.params.get(resLabel, 0, type=str)
        rawResult = rawResult.split(" ")
        rawResult = rawResult[:ORIGLENGTH]
        if (r == 0):
            for i in range(len(rawResult)):
                rawResult[i] = str(int(rawResult[i])/NUM_CLIENTS)
        RESULTS.append(rawResult)

    computeHHI()
    # print(RESULTS)
    sendResultsToClient();


## Resets the state for the next computation
@app.route('/reset')
def startNewComp():
    global CIPHERTEXT
    CIPHERTEXT = []
    global ENCRYPTED_RESULT
    ENCRYPTED_RESULT = []
    global DECRYPTION_SHARES
    DECRYPTION_SHARES = []
    global RESULTS
    RESULTS = []
    global CLIENT_NUMBER
    resetArgs = {'clientNum': str(CLIENT_NUMBER)}
    print("Sending reset request as client number: ", str(CLIENT_NUMBER))
    resetURL = urllib.parse.urlencode(resetArgs).encode('ascii')
    global SERVER_ADDRESS
    urllib.request.urlopen(SERVER_ADDRESS + "reset", resetURL)



######################
## File serving
######################

@app.route('/img/:path#.+#', name='img')
def server_static(path):
    return static_file(path, root='./img')

@app.route('/js/:path#.+#', name='js')
def server_static(path):
    return static_file(path, root='./js')

@app.route('/css/:path#.+#', name='css')
def server_static(path):
    return static_file(path, root='./css')

@app.route('/')
def index():
    return template('ipri-smpc-demo.html', request=request, url=url)
    # return template('py-demo/home_new.html', request=request)
    # return template('py-demo/index.html', request=request)

########################################################################################
## Launch code
########################################################################################

debug(True)

# run(host=CLIENT_ADDRESS, port=CLIENT_PORT)

from gevent.pywsgi import WSGIServer
from geventwebsocket import WebSocketError
from geventwebsocket.handler import WebSocketHandler
server = WSGIServer((CLIENT_ADDRESS, CLIENT_PORT), app, handler_class=WebSocketHandler)
server.serve_forever()
