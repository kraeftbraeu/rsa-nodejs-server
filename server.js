var http = require('http');
var url = require('url');

// parse request string
var querystring = require('querystring');

// file system
var fs = require('fs');

// decryption
var rsa = require('./rsa/rsa.js');
var rsa2 = require('./rsa/rsa2.js');

var port = 80;
http.createServer(function(request, response) {
	if(request.url.search(/^[\w\/]+\.?[\w]+$/) != -1)
	{
		if(request.method == 'POST' && request.url == '/login')
		{
			// ajax-request, read encrypted, decrypt, return values
			processLogin(request, response, function() {
				var decrypted = decrypt(request.post.encrypted);
				var ar = decrypted.split("\r\n");

				var jsonObj = JSON.stringify({'us': ar[0], 
											  'pw': ar[1], 
											  'ts': ar[2], 
											  'valid': isTimestampValid(ar[2])});
				response.writeHead(200, {'Content-Type': 'application/json'});
				response.end(jsonObj);
				console.log('  return login 200');
			});
		}
		else if(request.method == 'GET' && request.url == '/page')
		{
			// proxy html page in ../mk-jsrsa for cross site request
			fs.readFile('../mk-jsrsa/rsa-client.htm', function(err, fileContent) {
				if(err)
					throw err;
				response.writeHead(200, {'Content-Type': 'text/html'});
				response.end(fileContent);
				console.log('  return page 200');
			});
		}
		else if(request.method == 'GET' && request.url.substr(-3) === '.js')
		{
			// proxy js file in ../mk-jsrsa for cross site request
			fs.readFile('../mk-jsrsa' + request.url, function(err, fileContent) {
				if(err)
					throw err;
				response.writeHead(200, {'Content-Type': 'text/javascript'});
				response.end(fileContent);
				console.log('  return js 200');
			});
		}
		else
		{
			// check 'valid' URL consisting of letters, slashes and file extension
			var path = request.url.split(/\//g);
			var res = 'path:\n';
			var i;
			for(i=0; i<path.length; i++)
				res += '  ' + path[i] + '\n';
			response.writeHead(200, {'Content-Type': 'text/plain'});
			response.end(res);
			console.log('  return 200');
		}
	}
	else
	{
		// return 404
		response.writeHead(404);
		response.end();
		console.log('  return 404');
	}
}).listen(port);
console.log('  server started, listening to http://localhost:' + port);

function processLogin(request, response, callback)
{
	var body = '';
	request.on('data', function (data){
		body += data;
		if(body.length > 1e6)
		{
			// deny huge requests
			response.writeHead(413);
			request.connection.destroy();
			console.log('  return 413');
		}
	});
	request.on('end', function() {
		request.post = querystring.parse(body);
		callback();
	});
}

function decrypt(encrypted)
{
	var Nstr = "81818f464f217191b3dec5d39ab69d851d11043cc107a7a754dbbd47ed0cbaacfe5efcbd8eda1de838a15f34739dffc8fb62c00be385c6d4f5d2ac65c1d3a30c9f8c61442862d2b91ecbc94b8621057b642fcd459f9471dcf6b7c6ded0837d38b579b0a11bfcfdfaab468620edff75393d40f2a209e4d284819f05b38e38939c4ca2a21cad67b1fded2ff78602092fd53273d620b5d5f21760e60f8687b0a5970fdfcca198c7413bc90f26d2994d62e3f89a1932e4e9ea0a857b948613b673f3aba2fecb567d9b8cac3856444be36e7dcad6ad8f226254d3a62a94c4c6f4aaccb2105b9f4b4717cc6b8bba84a887a8b8cecc8a941d17dfd3fb1d9ffb0836915d";
	var estr = "10001";
	var dstr = "4d1d48a3251b54f4dd961956171a0651ed2ce4c90867f67cbd1adb6aa8cc9b9bc71be883373cc9f22d4669da61be034139ef634bb0ff4796278a7afd5c9d18c9bb776bb39a18be415d051ba7cd067cad2ccb0a001b35d95729d1e4a9689fe340914f14cdda4c9b2f582d7650c56707f63d731f073dbcf35dd3914d63cd9c02c87f2a5246bde8fe727ac9012c893b2266f03ecb3e0fe4a98fc2c260b98a5f5c4851783120e5f03a61775e310c13fa1fa5a5d92671c770c1de9f2f16ae3a970a4ecc929cb192e316422ad9c28f925e88eaf3553fc80f8abbd4c565720beaabd2c12a0be836d1670ca9ae7b89fc724262647a91a883fcc3c9b9472a39ab6537ea5";
	var rsakey = new rsa.RSAKey();
	rsakey.setPrivate(Nstr, estr, dstr);
	return rsakey.decrypt(encrypted);
}

function isTimestampValid(ts)
{
	var now = Date.now();
	var diff = now - ts;
	console.log("  age of ts: " + diff);
	if(diff < 0)
		return false;
	if(diff > 10*1000) // 10sec
		return false;
	return true;
}