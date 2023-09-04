from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
import platform
import datetime
import inspect
import hashlib
import socket
import random
import rsa
import sys
import os

###* VARS *###

DEFAULT_BUFFER = 4096
DEFAULT_HOST = ''
DEFAULT_PORT = 213

DEFAULT_RSA_KEY_LENGTH = 4096

DIRNAME = ''
WIN_DIRNAME = '.'
LINUX_DIRNAME = '/home/pi/pyvault'

PSW_DIRNAME = 'data'
LOG_DIRNAME = 'logs'
RSA_DIRNAME = 'rsa'

COMM_KEY_FILENAME = 'comm'
CESAR_SHIFT_FILENAME = 'shift'
DATABASE_FILENAME = 'db'

RSA_PRIV_CLIENT_KEY_FILENAME = 'privclient'
RSA_PUB_CLIENT_KEY_FILENAME = 'pubclient'
RSA_PRIV_SERVER_KEY_FILENAME = 'privserver'
RSA_PUB_SERVER_KEY_FILENAME = 'pubserver'

KEY_EXT = '.key'
PSW_EXT = '.pyv'
LOG_EXT = '.log'
RSA_EXT = '.pem'
SHIFT_EXT = '.sft'
DB_EXT = '.pyvdb'

###* ACTION CLASSES *###

#? An action is everything that servers does with the received data + errors occured during runtime
#? Number in type array is argument count; positive: exact X, negative: at least X, can be more

class ActionData:
  ADD_DATA = ['action_add_data', -1]
  GET_DATA = ['action_get_data', 2]
  ERROR = ['action_error', 2]
  CHECK = ['action_check', 1]
  CHECK_OK = ['action_check_ok', 0]
  DATA_ADDED = ['action_data_added', 1]
  DATA_GOT = ['action_data_got', -1]


class Action:
  def __init__(self, type: ActionData, data: list[str]):
    self.type = type
    self.data = data
  
  def getType(self) -> ActionData:
    return self.type
  
  def getData(self) -> list[str]:
    return self.data


class Error(Action):
  def __init__(self, description, place):
    super(Error, self).__init__(ActionData.ERROR[0], [description, place])

  def getDesc(self) -> str:
    return self.data[0]
  
  def getPlace(self) -> str:
    return self.data[1]


class ActionManager:
  def __init__(self):
    pass
  
  def validate(self, data: list[str]) -> bool:
    for mem in inspect.getmembers(ActionData)[:7]:
      typeArray = mem[1]

      if data[0] == typeArray[0]:
        reqArgs = typeArray[1]
        args = len(data) - 1
        
        if reqArgs > 0:
          if args == reqArgs:
            return True
          
        if reqArgs == 0 and args == 0:
          return True
        
        if reqArgs < 0:
          reqArgsPos = (reqArgs * -1)
          if args >= reqArgsPos:
            return True

        return False

  def handle(self, action: Action) -> None:
    actionType = action.getType()

    if actionType == ActionData.ADD_DATA[0]:
      self.logger.log(f'{self.server.addr[0]} sent {actionType}')
      key = self.datamg.addData(action.data)
      self.comm.send([ActionData.DATA_ADDED[0], key])
      self.logger.log(f'sent {ActionData.DATA_ADDED[0]} to {self.server.addr[0]}')
      self.server.disConn()

    if actionType == ActionData.GET_DATA[0]:
      self.logger.log(f'{self.server.addr[0]} sent {actionType}')
      key = b64decode(action.data[1])
      data = self.datamg.getData(action.data[0], key)
      self.comm.send([ActionData.DATA_GOT[0]] + data)
      self.logger.log(f'sent {ActionData.DATA_GOT[0]} to {self.server.addr[0]}')
      self.server.disConn()

    if actionType == ActionData.ERROR[0]:
      self.logger.log(f'an error occured: {action.data[0]} at {action.data[1]}')
      self.comm.send([ActionData.ERROR[0]] + action.data)
      self.server.disConn()

    if actionType == ActionData.CHECK[0]:
      self.logger.log(f'{self.server.addr[0]} sent {actionType}')
      self.comm.send([ActionData.CHECK_OK[0], action.data[0]])
      self.logger.log(f'sent {ActionData.CHECK_OK[0]} to {self.server.addr[0]}')
      self.server.disConn()


###* MAIN CLASSES *###

class Server:
  def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, defaultBuffer: int = DEFAULT_BUFFER):
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    self.host = host
    self.port = port
    self.defaultBuffer = defaultBuffer

    self.socket.bind((host, port))
    self.socket.listen()

    self.conn = None
    self.addr = None
    self.connected = False
  
  def listenForConn(self) -> None:
    self.conn, self.addr = self.socket.accept()
    self.connected = True
    self.logger.log(f'{self.addr[0]} connected')
    self.comm.recvData()
  
  def disConn(self) -> None:
    addr = self.addr[0]
    self.conn.close()
    self.logger.log(f'{addr} disconnected')
    self.listenForConn()
  
  def __del__(self):
    self.socket.close()


class Comm:
  def __init__(self):
    pass

  def send(self, msg: list[str]) -> None:
    sendData = self.crypt.commEncrypt(msg)

    self.server.conn.sendall(sendData)
  
  def recv(self, buffer: int = DEFAULT_BUFFER) -> str:
    while True:
      if self.server.connected:
        recvData = self.server.conn.recv(buffer)
        if recvData: break

    data = recvData.decode()

    return data
  
  def recvData(self) -> None:
    r = self.recv()

    data = self.crypt.commDecrypt(r)
      
    if self.actionManager.validate(data):
      self.actionManager.handle(Action(data[0], data[1:]))

class Crypt:
  def __init__(self):
    if not os.path.exists(f'{DIRNAME}/{COMM_KEY_FILENAME}{KEY_EXT}'):
      self.createCommKey(256)
    
    if not os.path.exists(f'{DIRNAME}/{PSW_DIRNAME}'):
      os.mkdir(f'{DIRNAME}/{PSW_DIRNAME}')

    if not os.path.exists(f'{DIRNAME}/{RSA_DIRNAME}'):
      os.mkdir(f'{DIRNAME}/{RSA_DIRNAME}')

  def createDataKey(self, size: int) -> bytes:
    if size == 128: size = 16
    if size == 192: size = 24
    if size == 256: size = 32

    return get_random_bytes(size)
  
  def createCommKey(self, size) -> None:
    keyBytes = self.createDataKey(size)
    with open(f'{DIRNAME}/{COMM_KEY_FILENAME}{KEY_EXT}', 'w+') as keyfile:
      keyfile.write(f'{str(b64encode(keyBytes))[2:-1]}\n')
  
  def readCommKey(self) -> bytes:
    try:
      with open(f'{DIRNAME}/{COMM_KEY_FILENAME}{KEY_EXT}', 'r') as keyfile:
        return b64decode(keyfile.read())
    except:
      self.actionManager.handle(Error('could not read comm key', 'Crypt.readCommKey'))
  
  def isBase64(data: str) -> bool:
    if b64encode(b64decode(data.encode())) == data: return True
    else: return False

  def encrypt(self, data: bytes, key: bytes) -> list[bytes]:
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce

    try:
      cipherdata, tag = cipher.encrypt_and_digest(data)
      return [cipherdata, tag, nonce]
    except:
      self.actionManager.handle(Error('could not encrypt the data', 'Crypt.encrypt'))

  def commEncrypt(self, data: list[str]) -> bytes:
    bytesStr = str('\n'.join(data)).encode()

    rsaCrypted = self.rsaEncrypt(bytesStr)

    commKey = self.readCommKey()
    cesarShift = self.readShift()
    crypted = self.encrypt(rsaCrypted, commKey)
    
    data = self.b64Encode(crypted)
    
    sendData = str(b64encode('\n'.join(data).encode()))[2:-1]
    scrambled = self.cesar(sendData, cesarShift)

    return scrambled.encode()

  def b64Encode(self, data: list[bytes]) -> list[str]:
    b64data = []

    for d in data:
      enc = str(b64encode(d))[2:-1]
      b64data.append(enc)
    
    return b64data

  def decrypt(self, data: list[bytes], key: bytes) -> list[str]:
    try:
      cipherdata = data[0]
      tag = data[1]
      nonce = data[2]

      cipher = AES.new(key, AES.MODE_EAX, nonce)

      plaindata = cipher.decrypt_and_verify(cipherdata, tag)

      return plaindata
    except:
      self.actionManager.handle(Error('could not decrypt the data', 'Crypt.decrypt'))
      pass

  def commDecrypt(self, data: str) -> list[str]:
    commKey = self.readCommKey()
    cesarShift = self.readShift()

    try:
      unscrambled = self.cesar(data, -cesarShift).encode()
      b64arr = str(b64decode(unscrambled))[2:-1].split('\\n')
      bytesArr = self.b64Decode(b64arr)

      rsaData = self.decrypt(bytesArr, commKey)
      rsaDecrypted = self.rsaDecrypt(rsaData).decode()

      plainArr = rsaDecrypted.split('\n')
    
      return plainArr
    except:
      self.actionManager.handle(Error('could not decrypt data', 'Crypt.commDecrypt'))

  def b64Decode(self, data: list[str]) -> list[bytes]:
    bData = []

    for d in data:
      dec = b64decode(d)
      bData.append(dec)
    
    return bData
  
  def cesar(self, data: str, shift: int) -> str:
    res = ''
    nums = list(range(48, 58)) + [61] + list(range(65, 91)) + list(range(97, 123))
    numCount = len(nums)

    if shift < 0:
      rev = (shift * -1) % numCount
      shift = numCount - rev

    for c in data:
      idx = nums.index(ord(c)) + shift
      if idx >= numCount:
        idx = idx % numCount

      res += chr(nums[idx])
    
    return res
  
  def createRsaKeys(self, length) -> None:
    print(f'Generating RSA {length} bits key pair..')
    pub, priv = rsa.newkeys(length, poolsize=4)
    print(f'Done! Saving into {RSA_PUB_CLIENT_KEY_FILENAME}{RSA_EXT} & {RSA_PRIV_SERVER_KEY_FILENAME}{RSA_EXT}')

    with open(f'{DIRNAME}/{RSA_DIRNAME}/{RSA_PUB_CLIENT_KEY_FILENAME}{RSA_EXT}', 'wb') as pubkeyfile:
      pubkeyfile.write(pub._save_pkcs1_pem())
    
    with open(f'{DIRNAME}/{RSA_DIRNAME}/{RSA_PRIV_SERVER_KEY_FILENAME}{RSA_EXT}', 'wb') as privkeyfile:
      privkeyfile.write(priv._save_pkcs1_pem())
  
  def md5(self, data: str) -> str:
    hashed = hashlib.md5(data.encode()).hexdigest()
    return hashed
  
  def createShift(self) -> None:
    shift = str(random.randint(1, 9999))
    pad = 4 - len(shift)
    shift = pad * '0' + shift
    
    with open(f'{DIRNAME}/{CESAR_SHIFT_FILENAME}{SHIFT_EXT}', 'w+') as shiftfile:
      shiftfile.write(str(b64encode(shift.encode()))[2:-1])
    
    print(f'Done! New shift written to {CESAR_SHIFT_FILENAME}{SHIFT_EXT} file')
    exit()
  
  def readShift(self) -> int:
    try:
      with open(f'{DIRNAME}/{CESAR_SHIFT_FILENAME}{SHIFT_EXT}', 'r') as shiftfile:
        shiftB64 = shiftfile.read().strip()

      shift = int(str(b64decode(shiftB64))[2:-1])
      
      return shift
    except:
      pass
  
  def readRsaPub(self) -> rsa.PublicKey:
    try:
      with open(f'{RSA_DIRNAME}/{RSA_PUB_SERVER_KEY_FILENAME}{RSA_EXT}', 'rb') as rsapub:
        key = rsa.PublicKey._load_pkcs1_pem(rsapub.read())
      
      return key
    except:
      self.actionManager.handle(Error('could not read rsa public key', 'Crypt.readRsaPub'))
  
  def readRsaPriv(self) -> rsa.PrivateKey:
    try:
      with open(f'{RSA_DIRNAME}/{RSA_PRIV_SERVER_KEY_FILENAME}{RSA_EXT}', 'rb') as rsapriv:
        key = rsa.PrivateKey._load_pkcs1_pem(rsapriv.read())
      
      return key
    except:
      self.actionManager.handle(Error('could not read rsa private key', 'Crypt.readRsaPriv'))
  
  def rsaEncrypt(self, data: bytes) -> bytes:
    key = self.readRsaPub()
    crypted = rsa.encrypt(data, key)
    return crypted

  def rsaDecrypt(self, crypted: bytes) -> bytes:
    key = self.readRsaPriv()
    data = rsa.decrypt(crypted, key)
    return data


class Logger:
  def __init__(self):
    if not os.path.exists(LOG_DIRNAME):
      os.mkdir(f'{DIRNAME}/{LOG_DIRNAME}')
  
  def log(self, data: str) -> None:
    logFilename = str(datetime.date.today())
    timestamp = str(datetime.datetime.now())
    logStr = f'[{timestamp}] : {data}'
    print(logStr) #! DEBUG

    with open(f'{LOG_DIRNAME}/{logFilename}{LOG_EXT}', 'a+') as logfile:
      logfile.write(f'{logStr}\n')


class DataMg:
  def __init__(self):
    pass

  def addData(self, data: list[str]) -> str:
    filenamePlain = ''

    for x in data:
      if 'label:' in x:
        filenamePlain = x.split(':')[1]
        data.remove(x)
    
    filename = hashlib.md5(filenamePlain.encode()).hexdigest()

    key = self.crypt.createDataKey(256)
    dataStr = '\n'.join(data).encode()
    crypted = self.crypt.encrypt(dataStr, key)

    with open(f'{DIRNAME}/{PSW_DIRNAME}/{filename}{PSW_EXT}', 'w+') as passfile:
      passfile.write(f'{str(b64encode(crypted[0]))[2:-1]}\n')
      passfile.write(f'{str(b64encode(crypted[1]))[2:-1]}\n')
      passfile.write(f'{str(b64encode(crypted[2]))[2:-1]}\n')
    
    return str(b64encode(key))[2:-1]
  
  def getData(self, label: str, key: bytes) -> list[str]:
    filename = self.crypt.md5(label)

    with open(f'{DIRNAME}/{PSW_DIRNAME}/{filename}{PSW_EXT}', 'r') as passfile:
      data = passfile.read()
    
    dataArr = data.split('\n')
    bytesArr = self.crypt.b64Decode(dataArr)
    
    decrypted = self.crypt.decrypt(bytesArr, key).decode().split('\n')
    
    return decrypted


###* MAIN THREAD *###

def main():
  if '--gen-rsa' in sys.argv:
    crypt = Crypt()
    crypt.createRsaKeys(DEFAULT_RSA_KEY_LENGTH)
    exit()
  
  if '--gen-shift' in sys.argv:
    crypt = Crypt()
    crypt.createShift()

  #? Create class instances
  actionManager = ActionManager()
  logger = Logger()

  server = Server()
  server.actionManager = actionManager
  server.logger = logger

  comm = Comm()
  server.comm = comm

  crypt = Crypt()
  crypt.actionManager = actionManager
  crypt.logger = logger

  datamg = DataMg()
  datamg.crypt = crypt

  comm.actionManager = actionManager
  comm.server = server
  comm.crypt = crypt
  comm.logger = logger

  actionManager.server = server
  actionManager.comm = comm
  actionManager.crypt = crypt
  actionManager.logger = logger
  actionManager.datamg = datamg

  server.listenForConn()

if __name__ == '__main__':
  if platform.system() == 'Windows':
    DIRNAME = WIN_DIRNAME
  
  if platform.system() == 'Linux':
    DIRNAME = LINUX_DIRNAME
  
  main()
