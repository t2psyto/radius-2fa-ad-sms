// requirements
var radius = require('radius')
var dgram = require("dgram")
var request = require('request')
var activedirectory = require('activedirectory')

// new udp server
var server = dgram.createSocket("udp4")

//active directory setup
var adconfig = require('./adconfig')
var ad = new activedirectory(adconfig)

// highside message api URL (to send txt messages)
//var highside = 'https://api01.highside.net/start/aaaaaaaaaa?number=' // needs to be edited to a functional API URL to send text

var countrycode = "+81"

// Download the helper library from https://jp.twilio.com/docs/node/install
// Find your Account SID and Auth Token at twilio.com/console
// and set the environment variables. See http://twil.io/secure
const accountSid = "TWILIO_ACCOUNT_SID";
const authToken = "TWILIO_AUTH_TOKEN";
const client = require('twilio')(accountSid, authToken);

// twilio sms src number
var smssrc = 'TWILIO_ACTIVE_NUMBER';

//var sendTextTo = 'mobile' // refers to the LDAP attribute with the number. use mobile for AD Mobile Number, use telephoneNumber for regular AD Telephone Number.

var domainify = function(name) {
	return name+'@'+adconfig.domain
}

// radius secret
var secret = 'radius_secret'

// challange timeout in minutes
//var timeout = 2

// use challenges array as temporary store
var challenges = []


server.on("message", function (msg, rinfo) {
	var code, username, password, packet
	var sendResponse = function(code) {
		var response = radius.encode_response({
			packet: packet,
			code: code,
			secret: secret
		});

		console.log('Sending ' + code + ' for user ' + username)
		server.send(response, 0, response.length, rinfo.port, rinfo.address, function(err, bytes) {
			if (err) {
				console.log('Error sending response to ', rinfo)
			}
		});
	}
	packet = radius.decode({packet: msg, secret: secret})

	if (packet.code != 'Access-Request') {
		console.log('unknown packet type: ', packet.code)
		return;
	}

	username = packet.attributes['User-Name']
	password = packet.attributes['User-Password']

	console.log('Access-Request for ' + username)

	var findUserInAd = function(name, cb) {
		// get info on requesting user
		ad.findUser(domainify(name), function(err, user) {
			if (err) {
				console.log('ERROR: ' +JSON.stringify(err))
				cb(undefined)
				return;
			}
			if (!user) {
				console.log('User: ' + domainify(username) + ' not found.')
				cb(undefined)
			} else {
				cb(user)
			}
		})
	}

	var checkChallenges = function(cb) {
		if (challenges.length > 0) {
			for (i=0; i<challenges.length; i++) {
				if (challenges[i].sAMAccountName == username) {
					console.log('found challenge for user '+username)
					if(challenges[i].code == password) {
						console.log('correct code ' + password)
						challenges.splice(i,1);
						sendResponse('Access-Accept')
					} else {
						console.log('wrong code')
						challenges.splice(i,1);
						sendResponse('Access-Reject')
					}
				}
				if (i+1 == challenges.length) {
					console.log('no challenge for user '+username+' found')
					cb()
				}
			}
		} else {
			console.log('no challenges found')
			cb()
		}	
	}

	// get info on requesting user
	findUserInAd(username, function(user) {

		if (!user) {
			sendResponse('Access-Reject')
		} else {
			console.log(JSON.stringify(user))

			// check if challenge exists
			checkChallenges(function() {
				// if no challenge, check if AD account valid
				ad.authenticate(domainify(username), password, function(err, auth) {
					if (err) {
						console.log('ERROR: '+JSON.stringify(err));
						sendResponse('Access-Reject')
					}
					if (auth) {
						// set response code to 'access-challenge'
						
						// request sms at highside and send to user's phonenumber
						if (user.telephoneNumber) {
							
							// has phonenumber

							//prepare telephone number for international call
							var smsdest = countrycode + user.telephoneNumber.slice(1)

							console.log('sending text to this number: ' + smsdest)
							//#request.get(highside + user.telephoneNumber, function (error, response, body) {
							//#	if (!error && response.statusCode == 200) {
							//#		user.code = body
							//#		challenges.push(user)
							//#		sendResponse('Access-Challenge')
							//#	}
							//#})

							//send sms
							//get 6-digits as OTP code
							var otpcode = String(Math.floor( Math.random() * 1000000 )).padStart(6, '0');
							
							var smsmessage = "OTP code: " + otpcode
							console.log('OTP code:' + otpcode)
							client.messages
							      .create({from: smssrc, body: smsmessage, to: smsdest})
							      .then(message => {
									console.log('response: ----------------')
									console.log(message.sid);
									console.log('response: ----------------')
									//set otpcode as RADIUS password and request re-auth
									user.code = otpcode
									challenges.push(user)
							})
							sendResponse('Access-Reject')
						} else {
							console.log('No phone number found. Cannot send text')
							sendResponse('Access-Reject')
						}

					}
					else {
						console.log('Authentication failed!')
						sendResponse('Access-Reject')

					}
				})
			})
		}
	})
});

server.on("listening", function () {
	var address = server.address();
	console.log("radius server listening " +
		address.address + ":" + address.port);
});

server.bind(1812);
