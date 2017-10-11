#!/bin/sh
./cryptocurrency run --node-config testnet1/validators/0.toml --leveldb testnet1/validators/db/0 --public-api-address 127.0.0.1:8000 --private-api-address 127.0.0.1:8010 &
./cryptocurrency run --node-config testnet1/validators/1.toml --leveldb testnet1/validators/db/1 --public-api-address 127.0.0.1:8001 --private-api-address 127.0.0.1:8011 &
./cryptocurrency run --node-config testnet1/validators/2.toml --leveldb testnet1/validators/db/2 --public-api-address 127.0.0.1:8002 --private-api-address 127.0.0.1:8012 &
./cryptocurrency run --node-config testnet1/validators/3.toml --leveldb testnet1/validators/db/3 --public-api-address 127.0.0.1:8003 --private-api-address 127.0.0.1:8013 &
