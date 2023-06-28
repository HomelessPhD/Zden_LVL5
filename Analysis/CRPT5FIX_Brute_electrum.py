from BrainWallet import BrainWallet
from requests import get
from time import sleep

import sys
import asyncio
import os

from electrum import bitcoin
from electrum.util import json_encode, print_msg, create_and_start_event_loop, log_exceptions
from electrum.simple_config import SimpleConfig

from electrum import constants
from electrum.daemon import Daemon

loop, stopping_fut, loop_thread = create_and_start_event_loop()
config = SimpleConfig({"testnet": False})
constants.set_mainnet()
daemon = Daemon(config, listen_jsonrpc=False)
network = daemon.network
assert network.asyncio_loop.is_running()


BW = BrainWallet()

count = 0
with open("keys.txt") as fp:
    while True:
        count += 1
        key = fp.readline()  
        if not key:
            break      
        #if (count % 10) == 1:
        #    print('Now at '+str(count))
         
        private_key = key.rstrip('\n')        
        address = BW.generate_address_from_private_key(private_key)
        
        print(f'{count} | {address}')

        try:
            sh = bitcoin.address_to_scripthash(address)
            try:
                amount_of_txs = len( network.run_from_another_thread(network.get_history_for_scripthash(sh)) )
            except Exception as e:
                print('CATCHED========================================================================')
                print(str(e))
                amount_of_txs = -1
            if (amount_of_txs !=0):    
                balance_json = network.run_from_another_thread(network.get_balance_for_scripthash(sh))
                balance = max(balance_json['confirmed'],balance_json['unconfirmed'])
            else:
                blanace = 0

            sleep(0.5)
            
        except ValueError:
            print(f'Instance: [{private_key}] - ValueError address: {address}\n')
            continue

        if amount_of_txs > 0:
            with open('found.txt', 'a') as result:
                result.write(f'{balance} | {amount_of_txs}|{address} | {private_key}\n')
            print(f'Instance: [{private_key}] - Added address to found.txt\n')
        if amount_of_txs == -1:
            with open('found.txt', 'a') as result:
                result.write(f'{balance} | MANY | {address} | {private_key}\n')
            print(f'Instance: [{private_key}] - Added address to found.txt\n')

stopping_fut.set_result(1)
