extern crate serde_json;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate exonum;
extern crate router;
extern crate bodyparser;
extern crate iron;

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

use std::collections::HashMap;

use exonum::blockchain::{self, Blockchain, Service, GenesisConfig, ConsensusConfig, ValidatorKeys,
                         Transaction, ApiContext};
use exonum::node::{Node, NodeConfig, NodeApiConfig, TransactionSend, ApiSender, NodeChannel};
use exonum::messages::{RawTransaction, FromRaw, Message};
use exonum::storage::{Fork, MapIndex, LevelDB, LevelDBOptions};
use exonum::crypto::{PublicKey, SecretKey, Hash, HexValue};
use exonum::encoding::{self, Field};
use exonum::api::{Api, ApiError};
use iron::prelude::*;
use iron::Handler;
use router::Router;


// // // // // // // // // // CONSTANTS // // // // // // // // // //
const STORAGE_PATH: &'static str = "~/.db";
// Define service ID for the service trait.

const SERVICE_ID: u16 = 1;

// Define constants for transaction types within the service.

const TX_CREATE_WALLET_ID: u16 = 1;

const TX_TRANSFER_ID: u16 = 2;

// Define initial balance of a newly created wallet.

const INIT_BALANCE: u64 = 100;

// // // // // // // // // // PERSISTENT DATA // // // // // // // // // //

// Declare the data to be stored in the blockchain. In the present case,
// declare a type for storing information about the wallet and its balance.

/// Declare a [serializable][1]
/// [1]: https://github.com/exonum/exonum-doc/blob/master/src/architecture/serialization.md
/// struct and determine bounds of its fields with `encoding_struct!` macro.
encoding_struct! {
    struct Wallet {
        const SIZE = 48;

        field pub_key:            &PublicKey  [00 => 32]
        field name:               &str        [32 => 40]
        field balance:            u64         [40 => 48]
    }
}

/// Add methods to the `Wallet` type for changing balance.
impl Wallet {
    pub fn increase(self, amount: u64) -> Self {
        let balance = self.balance() + amount;
        Self::new(self.pub_key(), self.name(), balance)
    }

    pub fn decrease(self, amount: u64) -> Self {
        let balance = self.balance() - amount;
        Self::new(self.pub_key(), self.name(), balance)
    }
}

// // // // // // // // // // DATA LAYOUT // // // // // // // // // //

/// Create schema of the key-value storage implemented by `MemoryDB`. In the
/// present case a `Fork` of the database is used.
pub struct CurrencySchema<'a> {
    view: &'a mut Fork,
}

/// Declare layout of the data. Use an instance of [`MapIndex`][2]
/// [2]: https://github.com/exonum/exonum-doc/blob/master/src/architecture/storage.md#mapindex
/// to keep wallets in storage. Index values are serialized `Wallet` structs.
///
/// Isolate the wallets map into a separate entity by adding a unique prefix,
/// i.e. the first argument to the `MapIndex::new` call.
impl<'a> CurrencySchema<'a> {
    pub fn wallets(&mut self) -> MapIndex<&mut Fork, PublicKey, Wallet> {
        let prefix = blockchain::gen_prefix(SERVICE_ID, 0, &());
        MapIndex::new(prefix, self.view)
    }

    /// Get a separate wallet from the storage.
    pub fn wallet(&mut self, pub_key: &PublicKey) -> Option<Wallet> {
        self.wallets().get(pub_key)
    }
}

// // // // // // // // // // TRANSACTIONS // // // // // // // // // //

/// Create a new wallet.
message! {
    struct TxCreateWallet {
        const TYPE = SERVICE_ID;
        const ID = TX_CREATE_WALLET_ID;
        const SIZE = 40;

        field pub_key:     &PublicKey  [00 => 32]
        field name:        &str        [32 => 40]
    }
}

/// Transfer coins between the wallets.
message! {
    struct TxTransfer {
        const TYPE = SERVICE_ID;
        const ID = TX_TRANSFER_ID;
        const SIZE = 80;

        field from:        &PublicKey  [00 => 32]
        field to:          &PublicKey  [32 => 64]
        field amount:      u64         [64 => 72]
        field seed:        u64         [72 => 80]
    }
}

// // // // // // // // // // CONTRACTS // // // // // // // // // //

/// Execute a transaction.
impl Transaction for TxCreateWallet {
    /// Verify integrity of the transaction by checking the transaction
    /// signature.
    fn verify(&self) -> bool {
        self.verify_signature(self.pub_key())
    }

    /// Apply logic to the storage when executing the transaction.
    fn execute(&self, view: &mut Fork) {
        let mut schema = CurrencySchema { view };
        if schema.wallet(self.pub_key()).is_none() {
            let wallet = Wallet::new(self.pub_key(), self.name(), INIT_BALANCE);
            println!("Create the wallet: {:?}", wallet);
            schema.wallets().put(self.pub_key(), wallet)
        }
    }
}

impl Transaction for TxTransfer {
    /// Check if the sender is not the receiver. Check correctness of the
    /// sender's signature.
    fn verify(&self) -> bool {
        (*self.from() != *self.to()) && self.verify_signature(self.from())
    }

    /// Retrieve two wallets to apply the transfer. Check the sender's
    /// balance and apply changes to the balances of the wallets.
    fn execute(&self, view: &mut Fork) {
        let mut schema = CurrencySchema { view };
        let sender = schema.wallet(self.from());
        let receiver = schema.wallet(self.to());
        if let (Some(sender), Some(receiver)) = (sender, receiver) {
            let amount = self.amount();
            if sender.balance() >= amount {
                let sender = sender.decrease(amount);
                let receiver = receiver.increase(amount);
                println!("Transfer between wallets: {:?} => {:?}", sender, receiver);
                let mut wallets = schema.wallets();
                wallets.put(self.from(), sender);
                wallets.put(self.to(), receiver);
            }
        }
    }
}

// // // // // // // // // // REST API // // // // // // // // // //

/// Implement the node API.
#[derive(Clone)]
struct CryptocurrencyApi {
    channel: ApiSender<NodeChannel>,
    blockchain: Blockchain,
}

/// Shortcut to get data on wallets.
impl CryptocurrencyApi {
    fn get_wallet(&self, pub_key: &PublicKey) -> Option<Wallet> {
        let mut view = self.blockchain.fork();
        let mut schema = CurrencySchema { view: &mut view };
        schema.wallet(pub_key)
    }

    fn get_wallets(&self) -> Option<Vec<Wallet>> {
        let mut view = self.blockchain.fork();
        let mut schema = CurrencySchema { view: &mut view };
        let idx = schema.wallets();
        let wallets: Vec<Wallet> = idx.values().collect();
        if wallets.is_empty() {
            None
        } else {
            Some(wallets)
        }
    }
}

/// Add an enum which joins transactions of both types to simplify request
/// processing.
#[serde(untagged)]
#[derive(Clone, Serialize, Deserialize)]
enum TransactionRequest {
    CreateWallet(TxCreateWallet),
    Transfer(TxTransfer),
}

/// Implement a trait for the enum for deserialized `TransactionRequest`s
/// to fit into the node channel.
impl Into<Box<Transaction>> for TransactionRequest {
    fn into(self) -> Box<Transaction> {
        match self {
            TransactionRequest::CreateWallet(trans) => Box::new(trans),
            TransactionRequest::Transfer(trans) => Box::new(trans),
        }
    }
}

/// The structure returned by the REST API.
#[derive(Serialize, Deserialize)]
struct TransactionResponse {
    tx_hash: Hash,
}

/// Implement the `Api` trait.
/// `Api` facilitates conversion between transactions/read requests and REST
/// endpoints; for example, it parses `POSTed` JSON into the binary transaction
/// representation used in Exonum internally.
impl Api for CryptocurrencyApi {
    fn wire(&self, router: &mut Router) {
        let self_ = self.clone();
        let transaction = move |req: &mut Request| -> IronResult<Response> {
            match req.get::<bodyparser::Struct<TransactionRequest>>() {
                Ok(Some(transaction)) => {
                    let transaction: Box<Transaction> = transaction.into();
                    let tx_hash = transaction.hash();
                    self_.channel.send(transaction).map_err(ApiError::Events)?;
                    let json = TransactionResponse { tx_hash };
                    self_.ok_response(&serde_json::to_value(&json).unwrap())
                }
                Ok(None) => Err(ApiError::IncorrectRequest("Empty request body".into()))?,
                Err(e) => Err(ApiError::IncorrectRequest(Box::new(e)))?,
            }
        };

        // Gets status of all wallets.
        let self_ = self.clone();
        let wallets_info = move |_: &mut Request| -> IronResult<Response> {
            if let Some(wallets) = self_.get_wallets() {
                self_.ok_response(&serde_json::to_value(wallets).unwrap())
            } else {
                self_.not_found_response(
                    &serde_json::to_value("Wallets database is empty")
                        .unwrap(),
                )
            }
        };

        // Gets status of the wallet corresponding to the public key.
        let self_ = self.clone();
        let wallet_info = move |req: &mut Request| -> IronResult<Response> {
            let path = req.url.path();
            let wallet_key = path.last().unwrap();
            let public_key = PublicKey::from_hex(wallet_key).map_err(ApiError::FromHex)?;
            if let Some(wallet) = self_.get_wallet(&public_key) {
                self_.ok_response(&serde_json::to_value(wallet).unwrap())
            } else {
                self_.not_found_response(&serde_json::to_value("Wallet not found").unwrap())
            }
        };

        // Bind the transaction handler to a specific route.
        router.post("/v1/wallets/transaction", transaction, "transaction");
        router.get("/v1/wallets", wallets_info, "wallets_info");
        router.get("/v1/wallet/:pub_key", wallet_info, "wallet_info");
    }
}

// // // // // // // // // // SERVICE DECLARATION // // // // // // // // // //

/// Define the service.
struct CurrencyService;

/// Implement a `Service` trait for the service.
impl Service for CurrencyService {
    fn service_name(&self) -> &'static str {
        "cryptocurrency"
    }

    fn service_id(&self) -> u16 {
        SERVICE_ID
    }

    /// Implement a method to deserialize transactions coming to the node.
    fn tx_from_raw(&self, raw: RawTransaction) -> Result<Box<Transaction>, encoding::Error> {
        let trans: Box<Transaction> = match raw.message_type() {
            TX_TRANSFER_ID => Box::new(TxTransfer::from_raw(raw)?),
            TX_CREATE_WALLET_ID => Box::new(TxCreateWallet::from_raw(raw)?),
            _ => {
                return Err(encoding::Error::IncorrectMessageType {
                    message_type: raw.message_type(),
                });
            }
        };
        Ok(trans)
    }

    /// Create a REST `Handler` to process web requests to the node.
    fn public_api_handler(&self, ctx: &ApiContext) -> Option<Box<Handler>> {
        let mut router = Router::new();
        let api = CryptocurrencyApi {
            channel: ctx.node_channel().clone(),
            blockchain: ctx.blockchain().clone(),
        };
        api.wire(&mut router);
        Some(Box::new(router))
    }
}

// // // // // // // // // // ENTRY POINT // // // // // // // // // //

fn main() {
    exonum::helpers::init_logger().unwrap();

    println!("Creating in-memory database...");

    let database_options = LevelDBOptions {
        create_if_missing: true,
        error_if_exists: false,
        ..Default::default()
    };
    let db = LevelDB::open(format!("{}/db", STORAGE_PATH), database_options).unwrap();


    //let db = MemoryDB::new();
    let services: Vec<Box<Service>> = vec![Box::new(CurrencyService)];
    let blockchain = Blockchain::new(Box::new(db), services);


    //---------------------------------------

    fn get_file_contents(path: &Path) -> String {
        let mut f = File::open(path).unwrap();
        let mut c = String::new();
        f.read_to_string(&mut c).unwrap();
        c
    }


    let node_keys_buf = get_file_contents(Path::new("keys.keys"));
    let node_keys_strs: Vec<&str> = node_keys_buf.lines().collect();

    let consensus_public_key = PublicKey::from_hex(&node_keys_strs[0]).unwrap();
    let consensus_secret_key = SecretKey::from_hex(&node_keys_strs[1]).unwrap();

    let service_public_key = PublicKey::from_hex(&node_keys_strs[2]).unwrap();
    let service_secret_key = SecretKey::from_hex(&node_keys_strs[3]).unwrap();


    let validator_keys_buf = get_file_contents(Path::new("validator_pub_keys.keys"));
    let validator_keys_strs: Vec<&str> = validator_keys_buf.lines().collect();

    let mut i = 0;
    let mut validator_keys: Vec<ValidatorKeys> = Vec::new();
    while i <= 0 {
        ////////////
        let cons = PublicKey::from_hex(&validator_keys_strs[i]).unwrap();
        let serv = PublicKey::from_hex(&validator_keys_strs[i + 1]).unwrap();
        validator_keys.push(ValidatorKeys {
            consensus_key: cons,
            service_key: serv,
        });
        i += 2;
    }



    // let key: PublicKey = PublicKey::from_hex("16ef83ca4b231404daec6d07b24beb84d89c25944285d2e32a2dcf8f0f3eda72").unwrap();

    //let consensus_public_key = PublicKey::from_hex("16ef83ca4b231404daec6d07b24beb84d89c25944285d2e32a2dcf8f0f3eda72").unwrap();
    //let consensus_secret_key = SecretKey::from_hex("2a751e6595af66f7644bd33cf7710b6226cf8d0de4b3d18bc8fc2d80f19325a716ef83ca4b231404daec6d07b24beb84d89c25944285d2e32a2dcf8f0f3eda72").unwrap();

    //let service_public_key = PublicKey::from_hex("523ead8ea8457de570e165a512dd5d1b6688cb5757c3d744e03d1173f3e3e237").unwrap();
    //let service_secret_key = SecretKey::from_hex("18544ebbf3ceeeebca847fe6b4e6ce88f83fc92b6b0e24d5466f3cd08aea37bb523ead8ea8457de570e165a512dd5d1b6688cb5757c3d744e03d1173f3e3e237").unwrap();

    //let (consensus_public_key, consensus_secret_key) = (PublicKey::from_hex("16ef83ca4b231404daec6d07b24beb84d89c25944285d2e32a2dcf8f0f3eda72").unwrap(), SecretKey::from_hex("2a751e6595af66f7644bd33cf7710b6226cf8d0de4b3d18bc8fc2d80f19325a716ef83ca4b231404daec6d07b24beb84d89c25944285d2e32a2dcf8f0f3eda72"));
    //let (service_public_key, service_secret_key) = PublicKey::from_hex("16ef83ca4b231404daec6d07b24beb84d89c25944285d2e32a2dcf8f0f3eda72").unwrap();

    //println!("{}",key);

//    let validator_keys = ValidatorKeys {
//        consensus_key: consensus_public_key,
//        service_key: service_public_key,
//    };

    let consensus_config = ConsensusConfig {
        txs_block_limit: 1,
        ..Default::default()
    };

    let genesis = GenesisConfig::new_with_consensus(consensus_config, validator_keys.into_iter());

    let api_address = "0.0.0.0:8000".parse().unwrap();
    let api_cfg = NodeApiConfig {
        public_api_address: Some(api_address),
        enable_blockchain_explorer: true,
        state_update_timeout: 1_000,
        ..Default::default()
    };

    let peer_address = "0.0.0.0:8001".parse().unwrap();

    let node_cfg = NodeConfig {
        listen_address: peer_address,
        peers: vec![
            //"185.35.221.11:8000".parse().unwrap(),
            "185.35.221.11:8001".parse().unwrap(),
            "54.252.175.39:8001".parse().unwrap()
        ],
        service_public_key,
        service_secret_key,
        consensus_public_key,
        consensus_secret_key,
        genesis,
        external_address: None,
        network: Default::default(),
        whitelist: Default::default(),
        api: api_cfg,
        mempool: Default::default(),
        services_configs: Default::default(),
    };

    println!("Starting a single node...");
    let mut node = Node::new(blockchain, node_cfg);

    println!("Blockchain is ready for transactions!");
    node.run().unwrap();
}
