#    ____                  __            __  
#   / __ \_   _____  _____/ /___  ____  / /__
#  / / / / | / / _ \/ ___/ / __ \/ __ \/ //_/
# / /_/ /| |/ /  __/ /  / / /_/ / /_/ / ,<   
# \____/ |___/\___/_/  /_/\____/\____/_/|_|  

# Author: Will Binns (Threema ID: UFKZ739A | https://threema.ch)
# Description: Check to see if a link might potentially be malicious.
# GitHub Repository: Overlook (github.com/wbinns/overlook)
# License: Unlicense (unlicense.org)

# Load libraries
import requests
import urllib
import os
import json
import yaml
from flask import Flask, request
from two1.wallet import Wallet
from two1.bitserv.flask import Payment

# Init Flask, Wallet and Payment
app = Flask(__name__)
wallet = Wallet()
payment = Payment(app, wallet)

# Add 402
@app.route('/check')
@payment.required(2700)
def lookup_string():
    KEY = os.environ.get('KEY')
    URL = request.args.get('URL')
    link = requests.get('https://api.certly.io/v1/lookup?url='+URL+'&token='+KEY)
    return link.text

# Add Manifest
@app.route('/manifest')
def docs():
    '''
    Serves the app manifest to the 21 crawler.
    '''
    with open('manifest.yaml', 'r') as f:
        manifest_yaml = yaml.load(f)
    return json.dumps(manifest_yaml)

# Init Host
if __name__=='__main__':
    app.run(host='0.0.0.0', port='10112')
