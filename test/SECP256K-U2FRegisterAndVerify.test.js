const BankAccounts = artifacts.require('BankAccounts');

const virtualu2fToken = require('../../u2ftoken');
var URLSafeBase64 = require('urlsafe-base64');
const crypto = require('crypto');
const parser = require('tder')

contract("BankAccounts", async (accounts) => {
    let contract;
  
    beforeEach(async () => {
  
      // Create contract
      contract = await BankAccounts.deployed();
      token = new virtualu2fToken.U2FToken([], virtualu2fToken.Type.SECP256K1WithEthereumStyleKeccak);
  
  });


  it("SECP256K registration and verification", async() => {
    let appIDRaw = await contract.getIdentity();
    let appID = Buffer.from(String(appIDRaw).slice(2), 'hex');

    await registerToken(appID);
    let transactionChallenge = await contract.transferFunds(accounts[1], 1000);
    await verifyTransaction(appID, transactionChallenge);


    

  });


  async function verifyTransaction(appID, challenge) {
    let keyHandleRaw = await contract.getKeyHandle();
    let keyHandle = Buffer.from(String(keyHandleRaw).slice(2), 'hex');

    var registeredKey = {
      'version': "U2F_V2",
      'keyHandle': URLSafeBase64.encode(keyHandle)
    }

    var verificationRequest = {
      'version': 'U2F_V2',
      'type': 'u2f_sign_request',
      'appId': appID,
      'challenge': URLSafeBase64.encode(challenge),
      'registeredKeys': [registeredKey]
    };

    reponse = await token.HandleSignRequest(verificationRequest);

    let userPresence = getUserPresenceByte(response)
    let counter = getCounter(response)


    //verifyTransaction(bytes32 applicationParameter, bytes1 userPresence, bytes32 counter,
    //  bytes clientData, bytes signature, SigningAlgorithm signingAlgorithm, bytes32 transactionChallenge)

  }


  async function registerToken(appID) {
    let tx = await contract.getRegistrationChallenge();
    let result = tx.logs[0].args
    let challenge = Buffer.from(String(result["1"]).slice(2), 'hex');

    var registrationRequest = {
        'version': 'U2F_V2',
        'type': 'u2f_register_request',
        'appId': appID,
        'registerRequests': [{
            challenge: URLSafeBase64.encode(challenge),
        }]
    };
  
    response = await token.HandleRegisterRequest(registrationRequest)

    let calculatedAppID = '0x' + sha2(appID);
    let clientData = '0x' + Buffer.from(response.clientData, 'base64').toString('hex')
    let signature = '0x' + getSignature(response.registrationData);
    let keyHandle = '0x' + response.keyHandle
    console.log('keyHandle: ' + keyHandle)
    let publicKey = '0x' + getUserPublicKey(response.registrationData);
    let attestationKey = '0x' + getAttestationPublicKey(response.registrationData);

    let answerTX = await contract.answerRegistrationChallenge(calculatedAppID, clientData, 
                                                              keyHandle, publicKey, attestationKey, signature, 0);

    console.log('gas usage: ' + answerTX.receipt.cumulativeGasUsed)
    assert.equal(answerTX.logs[0].args.verified, true);
  }

  function getAttestationPublicKey(registrationData) {

    /*
     * | Reserved (1 Byte) | PKey (65 Bytes) | KeyHandleLength (1 Byte) | KeyHandle (KeyHandleLength Bytes)
     * | Attestation Certificate (variable bytes) | signature (71-73 Bytes)
     *
     */

    let dataBuf = URLSafeBase64.decode(registrationData);
    let keyHandleLength = dataBuf.readUInt8(66);

    let startOfCertificate = 67 + keyHandleLength;

    let lengthOfCertificate = dataBuf.readUInt16BE(startOfCertificate+2) + 4;
    let endOfCertificate = startOfCertificate + lengthOfCertificate;

    let certBuffer = dataBuf.slice(startOfCertificate, endOfCertificate);

    let certRaw = parser.parse(certBuffer)
    let publicKey = certRaw.child[0].child[6].child[1].data;

    return publicKey.slice(2);
  }


  function getSignature(registrationData) {

    /*
     * | Reserved (1 Byte) | PKey (65 Bytes) | KeyHandleLength (1 Byte) | KeyHandle (KeyHandleLength Bytes)
     * | Attestation Certificate (variable bytes) | signature (71-73 Bytes)
     *
     */

    let dataBuf = URLSafeBase64.decode(registrationData);
    let keyHandleLength = dataBuf.readUInt8(66);
    let startOfCertificate = 67 + keyHandleLength;
    let lengthOfCertificate = dataBuf.readUInt16BE(startOfCertificate+2) + 4;
    let endOfCertificate = startOfCertificate + lengthOfCertificate;

    let signature = dataBuf.slice(endOfCertificate)
    return signature.toString('hex');
  }

  function getUserPublicKey(registrationData) {

    /*
     * | Reserved (1 Byte) | PKey (65 Bytes) | KeyHandleLength (1 Byte) | KeyHandle (KeyHandleLength Bytes)
     * | Attestation Certificate (variable bytes) | signature (71-73 Bytes)
     *
     */

    let dataBuf = URLSafeBase64.decode(registrationData);
    return dataBuf.slice(1, 66).toString('hex');
  }

  function sha2(message) {
    return crypto.createHash('sha256').update(message).digest().toString('hex');
  }

});
  