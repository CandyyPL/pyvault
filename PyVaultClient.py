from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from colored import Fore, Style
from Crypto.Cipher import AES
import inspect
import hashlib
import socket
import rsa
import sys
import os

DEFAULT_BUFFER = 4096
DEFAULT_HOST = '192.168.0.100'
DEFAULT_PORT = 213

DEFAULT_RSA_KEY_LENGTH = 4096

DIRNAME = '.'

KEY_DIRNAME = 'keys'
RSA_DIRNAME = 'rsa'

COMM_KEY_FILENAME = 'comm'
CESAR_SHIFT_FILENAME = 'shift'

RSA_PRIV_CLIENT_KEY_FILENAME = 'privclient'
RSA_PUB_CLIENT_KEY_FILENAME = 'pubclient'
RSA_PRIV_SERVER_KEY_FILENAME = 'privserver'
RSA_PUB_SERVER_KEY_FILENAME = 'pubserver'

KEY_EXT = '.key'
RSA_EXT = '.pem'
SHIFT_EXT = '.sft'

class ActionData:
  ADD_DATA = ['action_add_data', 0]
  GET_DATA = ['action_get_data', 0]
  CHECK = ['action_check', 0]
  CHECK_OK = ['action_check_ok', 1]
  DATA_ADDED = ['action_data_added', 1]
  DATA_GOT = ['action_data_got', -1]
  ERROR = ['action_error', 2]
  DIS_CONN = ['action_disconnect', 0]


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

    if actionType == ActionData.ERROR[0]:
      print(f'an error occured: {Fore.red}{action.data[0]}{Style.reset} at {Fore.yellow}{action.data[1]}{Style.reset}')
      exit()

    if actionType == ActionData.CHECK_OK[0]:
      if action.data[0] == self.client.randDataCheck:
        print('Server responded with correct CRC')
      else:
        print('Server responded but with incorrect CRC')
      
      self.client.disConn()
      exit()
    
    if actionType == ActionData.DATA_ADDED[0]:
      key = action.data[0]
      self.datamg.saveKey(key)
      print('Data added!')
      self.client.disConn()
      exit()
    
    if actionType == ActionData.DATA_GOT[0]:
      print(f'Data for {Fore.blue}{self.client.label}{Style.reset}:')
      for d in action.data:
        pub, priv = d.split(':')
        print(f'{Fore.green}{pub}{Style.reset} : {Fore.red}{priv}{Style.reset}')

      self.client.disConn()
      exit()


class Client:
  def __init__(self):
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.connected = False
  
  def connect(self, host = DEFAULT_HOST, port = DEFAULT_PORT):
    try:
      self.socket.connect((host, port))
      self.connected = True
    except:
      self.actionManager.handle(Error('could not connect to remote server', 'Client.connect'))
  
  def disConn(self):
    self.socket.close()
  
  def validate(self, data: list[str]) -> bool:
    for mem in inspect.getmembers(ActionData)[:5]:
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

class Comm:
  def __init__(self):
    pass

  def send(self, msg: bytes) -> None:
    self.client.socket.sendall(msg)
  
  def recv(self, buffer: int = DEFAULT_BUFFER) -> str:
    while True:
      if self.client.connected:
        recvData = self.client.socket.recv(buffer)
        if recvData: break

    data = recvData.decode()

    return data
  
  def recvData(self) -> None:
    r = self.recv()

    data = self.crypt.commDecrypt(r)
    
    if self.actionManager.validate(data):
      self.actionManager.handle(Action(data[0], data[1:]))
    else:
      self.actionManager.handle(Error('received data is not valid action', 'Comm.recvData'))
  
  def checkServer(self):
    randData = str(b64encode(get_random_bytes(8)))[2:-1]
    self.client.randDataCheck = randData
    sendData = self.crypt.commEncrypt([ActionData.CHECK[0], randData])
    self.send(sendData)
    self.recvData()

class Crypt:
  def __init__(self):
    if not os.path.exists(f'{DIRNAME}/{KEY_DIRNAME}'):
      os.mkdir(f'{DIRNAME}/{KEY_DIRNAME}')
    
    if not os.path.exists(f'{DIRNAME}/{RSA_DIRNAME}'):
      self.actionManager.handle(Error('could not find RSA keys dir', 'Crypt.__init__'))
  
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
      self.actionManager.handle(Error('could not encrypt data', 'Crypt.encrypt'))

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
      self.actionManager.handle(Error('could not decrypt data', 'Crypt.decrypt'))

  def commDecrypt(self, data: str) -> list[str]:
    commKey = self.readCommKey()
    cesarShift = self.readShift()

    try:
      unscrambled = self.cesar(data, -cesarShift).encode()
      b64arr = str(b64decode(unscrambled))[2:-1].split('\\n')
      bytesArr = self.b64Decode(b64arr)

      decrypted = self.decrypt(bytesArr, commKey)

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
    print(f'Done! Saving into {RSA_PUB_SERVER_KEY_FILENAME}{RSA_EXT} & {RSA_PRIV_CLIENT_KEY_FILENAME}{RSA_EXT}')

    with open(f'{DIRNAME}/{RSA_DIRNAME}/{RSA_PUB_SERVER_KEY_FILENAME}{RSA_EXT}', 'wb') as pubkeyfile:
      pubkeyfile.write(pub._save_pkcs1_pem())
    
    with open(f'{DIRNAME}/{RSA_DIRNAME}/{RSA_PRIV_CLIENT_KEY_FILENAME}{RSA_EXT}', 'wb') as privkeyfile:
      privkeyfile.write(priv._save_pkcs1_pem())

  def md5(self, data: str) -> str:
    hashed = hashlib.md5(data.encode()).hexdigest()
    return hashed

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
      with open(f'{RSA_DIRNAME}/{RSA_PUB_CLIENT_KEY_FILENAME}{RSA_EXT}', 'rb') as rsapub:
        key = rsa.PublicKey._load_pkcs1_pem(rsapub.read())
      
      return key
    except:
      self.actionManager.handle(Error('could not read rsa public key', 'Crypt.readRsaPub'))
  
  def readRsaPriv(self) -> rsa.PrivateKey:
    try:
      with open(f'{RSA_DIRNAME}/{RSA_PRIV_CLIENT_KEY_FILENAME}{RSA_EXT}', 'rb') as rsapriv:
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


class DataMg:
  def __init__(self):
    if not os.path.exists(f'{DIRNAME}/{KEY_DIRNAME}'):
      os.mkdir(f'{DIRNAME}/{KEY_DIRNAME}')

  def saveKey(self, key: str) -> None:
    filename = self.crypt.md5(self.filename)

    with open(f'{DIRNAME}/{KEY_DIRNAME}/{filename}{KEY_EXT}', 'w+') as keyfile:
      keyfile.write(key)
  
  def getKey(self, label: str) -> str:
    filename = self.crypt.md5(label)
    
    try:
      with open(f'{DIRNAME}/{KEY_DIRNAME}/{filename}{KEY_EXT}', 'r') as keyfile:
        key = keyfile.read().strip()
      
      return key
    except:
      self.actionManager.handle(Error('could not read comm key file', 'DataMg.getKey'))


def main():
  if '--gen-rsa' in sys.argv:
    crypt = Crypt()
    crypt.createRsaKeys(DEFAULT_RSA_KEY_LENGTH)
    exit()

  actionManager = ActionManager()
  client = Client()
  comm = Comm()
  crypt = Crypt()
  datamg = DataMg()

  datamg.crypt = crypt
  datamg.actionManager = actionManager

  client.crypt = crypt
  client.comm = comm
  client.actionManager = actionManager

  comm.client = client
  comm.crypt = crypt
  comm.actionManager = actionManager

  crypt.actionManager = actionManager

  actionManager.client = client
  actionManager.comm = comm
  actionManager.crypt = crypt
  actionManager.datamg = datamg

  for arg in sys.argv:
    idx = sys.argv.index(arg)

    if arg == '--check':
      client.connect()
      comm.checkServer()
    
    if arg == '-a':
      data = sys.argv[idx+1:]
        
      for x in data:
        if 'label:' in x:
          filename = x.split(':')[1]
          datamg.filename = filename

      sendData = crypt.commEncrypt([ActionData.ADD_DATA[0]] + data)

      client.connect()
      comm.send(sendData)
      comm.recvData()
      
      actionManager.handle(Error('label not specified in data', 'main'))
      exit()
    
    if arg == '-g':
      label = sys.argv[idx+1]
      client.label = label

      key = datamg.getKey(label)

      sendData = crypt.commEncrypt([ActionData.GET_DATA[0], label, key])

      client.connect()
      comm.send(sendData)
      comm.recvData()

if __name__ == '__main__': main()
