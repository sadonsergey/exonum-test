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


const STORAGE_PATH: &'static str = "~/.gotocc";


// Service identifier
const SERVICE_ID: u16 = 1;

// Identifier for wallet creation transaction type
const TX_CREATE_WALLET_ID: u16 = 1;


const TX_CREATE_TASK_ID: u16 = 69;
const TX_CLOSE_TASK_ID: u16 = 70;

const TX_SUBMIT_SOLUTION_ID: u16 = 71;
const TX_ADMIN_EXAMINE_SOLUTION_ID: u16 = 72;
const TX_ACCEPT_SCHOLARSHIP_ID: u16 = 73;

const TX_ASSIGN_TASK_ID: u16 = 74;


// Starting balance of a newly created wallet
const INIT_BALANCE: u64 = 100;


const CT_ADMIN_ACCEPTANCE: u8 = 1;
const CT_ADMIN_REJECTION: u8 = 2;
const CT_ADMIN_NOT_VOTED: u8 = 0;

const CT_AUTHOR_ACCEPTANCE: u8 = 1;
const CT_AUTHOR_REJECTION: u8 = 2;
const CT_AUTHOR_NOT_VOTED: u8 = 0;

// -------- Currency Schema init -------- //

#[derive(Debug)]
pub struct CurrencySchema<'a> {
    view: &'a mut Fork,
}

impl<'a> CurrencySchema<'a> {
    pub fn wallets(&mut self) -> MapIndex<&mut Fork, PublicKey, Wallet> {
        let prefix = blockchain::gen_prefix(SERVICE_ID, 0, &());
        MapIndex::new(prefix, self.view)
    }

    pub fn wallet(&mut self, pub_key: &PublicKey) -> Option<Wallet> {
        self.wallets().get(pub_key)
    }

    pub fn tasks(&mut self) -> MapIndex<&mut Fork, Hash, ScholarshipTask> {
        let prefix = blockchain::gen_prefix(SERVICE_ID, 1, &());
        MapIndex::new(prefix, self.view)
    }

    pub fn task(&mut self, hash: &Hash) -> Option<ScholarshipTask> {
        self.tasks().get(hash)
    }

    pub fn solutions(&mut self) -> MapIndex<&mut Fork, Hash, ScholarshipSolution> {
        let prefix = blockchain::gen_prefix(SERVICE_ID, 2, &());
        MapIndex::new(prefix, self.view)
    }

    pub fn solution(&mut self, hash: &Hash) -> Option<ScholarshipSolution> {
        self.solutions().get(hash)
    }
}

// ------------------------------------- //


// -------- Wallet struct init -------- //

encoding_struct! {
    struct Wallet {
        const SIZE = 80;

        field pub_key: &PublicKey [00 => 32]

        field name:    &str       [32 => 40]
        field age:     &str       [40 => 48]
        field email:   &str       [48 => 56]
        field city:    &str       [56 => 64]
        field school:  &str       [64 => 72]

        field balance: u64        [72 => 80]
    }
}

impl Wallet {
    pub fn increase(&mut self, amount: u64) {
        let balance = self.balance() + amount;
        Field::write(&balance, &mut self.raw, 72, 80);
    }

    pub fn decrease(&mut self, amount: u64) {
        let balance = self.balance() - amount;
        Field::write(&balance, &mut self.raw, 72, 80);
    }
}

// ----------------------------------- //


// -------- ScholarshipTask struct init -------- //

encoding_struct! {
    struct ScholarshipTask {
        const SIZE = 25;

        field name:    &str [00 => 08]
        field desc:    &str [08 => 16]
        field reward:  u64  [16 => 24]
        field is_open: bool [24 => 25]
    }
}

impl ScholarshipTask {
    pub fn close(&mut self) {
        let is_open = false;
        Field::write(&is_open, &mut self.raw, 24, 25);
    }

    pub fn create(name: &str, desc: &str, reward: u64) -> ScholarshipTask {
        ScholarshipTask::new(name, desc, reward, true)
    }
}

// ----------------------------------- //

// ----------------------------------- //


// -------- ScholarshipSolution struct init -------- //

encoding_struct! {
    struct ScholarshipSolution {
        const SIZE = 74;

        field task_hash:         &Hash      [00 => 32]
        field author:            &PublicKey [32 => 64]
        field url:               &str       [64 => 72]
        field admin_acceptance:  u8         [72 => 73]
        field author_acceptance: u8         [73 => 74]
    }
}

impl ScholarshipSolution {
    pub fn create(hash: &Hash, author: &PublicKey) -> ScholarshipSolution {
        ScholarshipSolution::new(hash, author, "", CT_ADMIN_NOT_VOTED, CT_AUTHOR_NOT_VOTED)
    }

    pub fn submit_solution(&mut self, url: &str) {
        Field::write(&url, &mut self.raw, 64, 72);
    }

    pub fn admin_accept(&mut self) {
        Field::write(&CT_ADMIN_ACCEPTANCE, &mut self.raw, 72, 73);
    }

    pub fn admin_reject(&mut self) {
        Field::write(&CT_ADMIN_REJECTION, &mut self.raw, 72, 73);
    }

    pub fn author_accept(&mut self) {
        Field::write(&CT_AUTHOR_ACCEPTANCE, &mut self.raw, 73, 74);
    }

    pub fn author_reject(&mut self) {
        Field::write(&CT_AUTHOR_REJECTION, &mut self.raw, 73, 74);
    }
}

// ----------------------------------- //



// -------- TxCreateTask --------------------------- //

message! {
    struct TxCreateTask {
        const TYPE = SERVICE_ID;
        const ID = TX_CREATE_TASK_ID;
        const SIZE = 24;

        field name:   &str [00 => 08]
        field desc:   &str [08 => 16]
        field reward: u64  [16 => 24]
    }
}

impl Transaction for TxCreateTask {
    fn verify(&self) -> bool {
        let admin_key: PublicKey = PublicKey::new(
            [
                0x02,
                0xb9,
                0xc6,
                0x56,
                0x13,
                0x22,
                0xf6,
                0x8d,
                0x2c,
                0xf9,
                0x73,
                0xe8,
                0xd5,
                0x44,
                0xd9,
                0x17,
                0x16,
                0xbf,
                0x0b,
                0x04,
                0x87,
                0x49,
                0x14,
                0xf3,
                0x1d,
                0xcd,
                0xe6,
                0xde,
                0x99,
                0xc5,
                0xc9,
                0xa1,
            ],
        );
        self.verify_signature(&admin_key)
    }

    fn execute(&self, view: &mut Fork) {
        let mut schema = CurrencySchema { view };

        let task = ScholarshipTask::create(self.name(), self.desc(), self.reward());

        let hash = self.hash();

        println!("Create the task: {:?}", task);
        schema.tasks().put(&hash, task)
    }
}

// ------------------------------------------------- //

// -------- TxCloseTask --------------------------- //

message! {
    struct TxCloseTask {
        const TYPE = SERVICE_ID;
        const ID = TX_CLOSE_TASK_ID;
        const SIZE = 32;

        field task_hash:   &Hash [00 => 32]
    }
}

impl Transaction for TxCloseTask {
    fn verify(&self) -> bool {
        let admin_key: PublicKey = PublicKey::new(
            [
                0x02,
                0xb9,
                0xc6,
                0x56,
                0x13,
                0x22,
                0xf6,
                0x8d,
                0x2c,
                0xf9,
                0x73,
                0xe8,
                0xd5,
                0x44,
                0xd9,
                0x17,
                0x16,
                0xbf,
                0x0b,
                0x04,
                0x87,
                0x49,
                0x14,
                0xf3,
                0x1d,
                0xcd,
                0xe6,
                0xde,
                0x99,
                0xc5,
                0xc9,
                0xa1,
            ],
        );
        self.verify_signature(&admin_key)
    }

    fn execute(&self, view: &mut Fork) {
        let mut schema = CurrencySchema { view };

        let task = schema.task(self.task_hash());

        if let Some(mut task) = task {
            task.close();
            println!("Task closed: {:?}", task);

            let mut tasks = schema.tasks();
            tasks.put(self.task_hash(), task);
        }
    }
}

// ------------------------------------------------- //

// ------------ TxCreateSolution ------------------- //
message! {
    struct TxAssignTask {
        const TYPE = SERVICE_ID;
        const ID = TX_ASSIGN_TASK_ID;
        const SIZE = 64;

        field task_hash: &Hash      [00 => 32]
        field author:    &PublicKey [32 => 64]
    }
}

impl Transaction for TxAssignTask {
    fn verify(&self) -> bool {
        self.verify_signature(self.author())
    }

    fn execute(&self, view: &mut Fork) {
        let mut schema = CurrencySchema { view };

        if schema.tasks().contains(self.task_hash()) {
            let solution = ScholarshipSolution::create(self.task_hash(), self.author());

            let hash = self.hash();

            println!("Solution created: {:?}", solution);

            schema.solutions().put(&hash, solution);
        } else {
            println!("Assigning with invalid task hash");
        }
    }
}
// ------------------------------------------------- //

// ------------ TxCreateSolution ------------------- //
message! {
    struct TxSubmitSolution {
        const TYPE = SERVICE_ID;
        const ID = TX_SUBMIT_SOLUTION_ID;
        const SIZE = 40;

        field solution_hash: &Hash  [00 => 32]
        field url:           &str   [32 => 40]
    }
}

impl Transaction for TxSubmitSolution {
    fn verify(&self) -> bool {
        //self.verify_signature(self.author()) ?????
        true
    }

    fn execute(&self, view: &mut Fork) {
        let mut schema = CurrencySchema { view };

        if let Some(mut solution) = schema.solution(self.solution_hash()) {
            if self.verify_signature(solution.author()) {
                solution.submit_solution(self.url());

                println!("Solution submitted");

                let mut solutions = schema.solutions();
                solutions.put(self.solution_hash(), solution);
            } else {
                println!("Solution verification failed");
            }
        } else {
            println!("Solution not found")
        }
    }
}
// ------------------------------------------------- //

// -------- TxAdminExamineSolution --------------------------- //
message! {
    struct TxAdminExamineSolution {
        const TYPE = SERVICE_ID;
        const ID = TX_ADMIN_EXAMINE_SOLUTION_ID;
        const SIZE = 33;

        field solution_hash:    &Hash [00 => 32]
        field admin_acceptance: u8    [32 => 33]
    }
}

impl Transaction for TxAdminExamineSolution {
    fn verify(&self) -> bool {
        let admin_key: PublicKey = PublicKey::new(
            [
                0x02,
                0xb9,
                0xc6,
                0x56,
                0x13,
                0x22,
                0xf6,
                0x8d,
                0x2c,
                0xf9,
                0x73,
                0xe8,
                0xd5,
                0x44,
                0xd9,
                0x17,
                0x16,
                0xbf,
                0x0b,
                0x04,
                0x87,
                0x49,
                0x14,
                0xf3,
                0x1d,
                0xcd,
                0xe6,
                0xde,
                0x99,
                0xc5,
                0xc9,
                0xa1,
            ],
        );

        if self.admin_acceptance() != CT_ADMIN_ACCEPTANCE &&
            self.admin_acceptance() != CT_ADMIN_REJECTION
            {
                return false;
            }

        self.verify_signature(&admin_key)
    }

    fn execute(&self, view: &mut Fork) {
        let mut schema = CurrencySchema { view };

        let solution = schema.solution(self.solution_hash());

        if let Some(mut solution) = solution {
            match self.admin_acceptance() {
                CT_ADMIN_ACCEPTANCE => {
                    solution.admin_accept();
                    println!("Solution accepted: {:?}", solution);
                }
                CT_ADMIN_REJECTION => {
                    solution.admin_reject();
                    println!("Solution rejected: {:?}", solution);
                }
                _ => {
                    println!("Unknown acceptance id");
                }
            }


            let mut solutions = schema.solutions();
            solutions.put(self.solution_hash(), solution);
        }
    }
}

// ------------------------------------------------- //

// -------- TxAuthorExamineSolution --------------------------- //
message! {
    struct TxAcceptScholarship {
        const TYPE = SERVICE_ID;
        const ID = TX_ACCEPT_SCHOLARSHIP_ID;
        const SIZE = 65;



        field pub_key:           &PublicKey [00 => 32]
        field solution_hash:     &Hash      [32 => 64]
        field author_acceptance: u8         [64 => 65]
    }
}

impl Transaction for TxAcceptScholarship {
    fn verify(&self) -> bool {
        if self.author_acceptance() != CT_AUTHOR_ACCEPTANCE &&
            self.author_acceptance() != CT_AUTHOR_REJECTION
            {
                return false;
            }

        self.verify_signature(self.pub_key())
    }

    fn execute(&self, view: &mut Fork) {
        let mut schema = CurrencySchema { view };

        let solution = schema.solution(self.solution_hash());

        if let Some(mut solution) = solution {

            if self.verify_signature(solution.author()) {

                if solution.admin_acceptance() == CT_ADMIN_ACCEPTANCE {
                    match self.author_acceptance() {
                        CT_AUTHOR_ACCEPTANCE => {
                            solution.author_accept();
                            println!("Solution accepted: {:?}", solution);
                        }
                        CT_AUTHOR_REJECTION => {
                            solution.author_reject();
                            println!("Solution rejected: {:?}", solution);
                        }
                        _ => {
                            println!("Unknown acceptance id");
                        }
                    }


                    let mut solutions = schema.solutions();
                    solutions.put(self.solution_hash(), solution);
                }

            } else {
                println!("TxAcceptScholarship Author key differs from tx initiator");
            }

        }
    }
}
// ------------------------------------------------- //


// -------- Wallet registration transaction -------- //
message! {
    struct TxCreateWallet {
        const TYPE = SERVICE_ID;
        const ID = TX_CREATE_WALLET_ID;
        const SIZE = 72;

        field pub_key: &PublicKey  [00 => 32]

        field name:    &str       [32 => 40]
        field age:     &str       [40 => 48]
        field email:   &str       [48 => 56]
        field city:    &str       [56 => 64]
        field school:  &str       [64 => 72]

    }
}

impl Transaction for TxCreateWallet {
    fn verify(&self) -> bool {
        self.verify_signature(self.pub_key())
    }

    fn execute(&self, view: &mut Fork) {
        let mut schema = CurrencySchema { view };
        if schema.wallet(self.pub_key()).is_none() {
            let wallet = Wallet::new(
                self.pub_key(),
                self.name(),
                self.age(),
                self.email(),
                self.city(),
                self.school(),
                INIT_BALANCE,
            );
            println!("Create the wallet: {:?}", wallet);
            schema.wallets().put(self.pub_key(), wallet)
        }
    }

    fn info(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap()
    }
}
// ----------------------------------------------- //




// -------- Api and transaction pipeline initialisation -------- //
#[derive(Clone)]
struct CryptocurrencyApi {
    channel: ApiSender<NodeChannel>,
    blockchain: Blockchain,
}

impl CryptocurrencyApi {
    fn get_wallet(&self, pub_key: &PublicKey) -> Option<Wallet> {
        let mut view = self.blockchain.fork();
        let mut schema = CurrencySchema { view: &mut view };
        schema.wallet(pub_key)
    }

    fn get_open_cs(&self) -> Option<serde_json::Value> {
        let mut view = self.blockchain.fork();
        let mut schema = CurrencySchema { view: &mut view };

        let tasks = schema.tasks();

        let mut tasks_map: HashMap<Hash, ScholarshipTask> = HashMap::new();

        for (hash, task) in tasks.iter() {
            if task.is_open() {
                tasks_map.insert(hash, task);
            }
        }

        if tasks_map.is_empty() {
            return None;
        }

        return Some(serde_json::to_value(tasks_map).unwrap());
    }


    // костыль
    fn db_contains_task(&self, hash: &Hash) -> bool {
        let mut view = self.blockchain.fork();
        let mut schema = CurrencySchema { view: &mut view };

        schema.tasks().contains(hash)
    }
    // костыль
    fn db_contains_wallet(&self, key: &PublicKey) -> bool {
        let mut view = self.blockchain.fork();
        let mut schema = CurrencySchema { view: &mut view };

        schema.wallets().contains(key)
    }


    fn get_solutions_with_filter(
        &self,
        solution_filter: &Fn(&ScholarshipSolution) -> bool,
    ) -> Option<serde_json::Value> {
        let mut view = self.blockchain.fork();
        let mut schema = CurrencySchema { view: &mut view };

        let solutions_table = schema.solutions();

        let mut map: HashMap<Hash, ScholarshipSolution> = HashMap::new();

        for (hash, solution) in solutions_table.iter() {
            if self.db_contains_task(solution.task_hash()) &&
                self.db_contains_wallet(solution.author()) && solution_filter(&solution)
                {
                    map.insert(hash, solution);
                }
        }

        if map.is_empty() {
            return None;
        }

        return Some(serde_json::to_value(map).unwrap());
    }

    fn get_submitted_cs_by_user(&self, user_key: &PublicKey) -> Option<Vec<serde_json::Value>> {
        let mut view = self.blockchain.fork();
        let mut schema = CurrencySchema { view: &mut view };

        let solutions_table = schema.solutions();
        let solutions = solutions_table.values();

        let mut user_contracts: Vec<serde_json::Value> = Vec::new();

        for solution in solutions {
            if self.db_contains_task(solution.task_hash()) &&
                self.db_contains_wallet(solution.author()) && solution.author() == user_key
                {
                    if let Ok(json) = serde_json::to_value(solution) {
                        user_contracts.push(json);
                    } else {
                        println!("Could not serialize");
                    }
                }
        }

        if user_contracts.len() == 0 {
            return None;
        }

        return Some(user_contracts);
    }
}

#[serde(untagged)]
#[derive(Clone, Serialize, Deserialize)]
enum TransactionRequest {
    CreateWallet(TxCreateWallet),
    CreateTask(TxCreateTask),
    CloseTask(TxCloseTask),
    AssignTask(TxAssignTask),
    SubmitSolution(TxSubmitSolution),
    AdminExamineSoluton(TxAdminExamineSolution),
    AcceptScholarship(TxAcceptScholarship),
}

impl Into<Box<Transaction>> for TransactionRequest {
    fn into(self) -> Box<Transaction> {
        match self {
            TransactionRequest::CreateWallet(trans) => Box::new(trans),
            TransactionRequest::CreateTask(trans) => Box::new(trans),
            TransactionRequest::CloseTask(trans) => Box::new(trans),
            TransactionRequest::AssignTask(trans) => Box::new(trans),
            TransactionRequest::SubmitSolution(trans) => Box::new(trans),
            TransactionRequest::AdminExamineSoluton(trans) => Box::new(trans),
            TransactionRequest::AcceptScholarship(trans) => Box::new(trans),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TransactionResponse {
    tx_hash: Hash,
}


impl Api for CryptocurrencyApi {
    fn wire(&self, router: &mut Router) {
        let self_ = self.clone();
        let tx_handler = move |req: &mut Request| -> IronResult<Response> {
            match req.get::<bodyparser::Struct<TransactionRequest>>() {
                Ok(Some(tx)) => {
                    let tx: Box<Transaction> = tx.into();
                    let tx_hash = tx.hash();
                    self_.channel.send(tx).map_err(|e| ApiError::Events(e))?;
                    let json = TransactionResponse { tx_hash };
                    self_.ok_response(&serde_json::to_value(&json).unwrap())
                }
                Ok(None) => Err(ApiError::IncorrectRequest("Empty request body".into()))?,
                Err(e) => Err(ApiError::IncorrectRequest(Box::new(e)))?,
            }
        };

        fn not_voted(tx: &ScholarshipSolution) -> bool {
            tx.admin_acceptance() == 0
        }

        fn approved(tx: &ScholarshipSolution) -> bool {
            tx.admin_acceptance() == 1
        }

        // Solutions, submitted by user
        let self_ = self.clone();
        let submitted_contracts = move |req: &mut Request| -> IronResult<Response> {
            let path = req.url.path();
            let user_key = path.last().unwrap().clone();
            if let Ok(user_key) = PublicKey::from_hex(user_key) {
                if let Some(contracts) = self_.get_submitted_cs_by_user(&user_key) {
                    self_.ok_response(&serde_json::to_value(contracts).unwrap())
                } else {
                    self_.not_found_response(
                        &serde_json::to_value("No contracts submitted").unwrap(),
                    )
                }
            } else {
                self_.not_found_response(&serde_json::to_value("Wrong key format").unwrap())
            }
        };

        // Contracts, avaliable for assigning
        let self_ = self.clone();
        let open_contracts = move |_: &mut Request| -> IronResult<Response> {
            match self_.get_open_cs() {
                Some(contracts) => self_.ok_response(&contracts),
                None => {
                    self_.not_found_response(&serde_json::to_value("No open contracts avaliable")
                        .unwrap())
                }
            }
        };


        // Done contracts, avaliavle for voting
        let self_ = self.clone();
        let done_contracts = move |_: &mut Request| -> IronResult<Response> {
            match self_.get_solutions_with_filter(&not_voted) {
                Some(contracts) => self_.ok_response(&contracts),
                None => {
                    self_.not_found_response(&serde_json::to_value("No open contracts avaliable")
                        .unwrap())
                }
            }
        };

        // Contracts signed by admin
        let self_ = self.clone();
        let admin_contracts = move |_: &mut Request| -> IronResult<Response> {
            match self_.get_solutions_with_filter(&approved) {
                Some(contracts) => self_.ok_response(&contracts),
                None => {
                    self_.not_found_response(&serde_json::to_value("No open contracts avaliable")
                        .unwrap())
                }
            }
        };

        // Wallet info by wallet key
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
        let route_post = "/v1/wallets/transaction";
        router.post(&route_post, tx_handler, "transaction");

        router.get("/v1/wallet/:pub_key", wallet_info, "wallet_info");

        router.get(
            "v1/contracts/users/sent_by_user/:pub_key",
            submitted_contracts,
            "contracts submitted by user",
        );
        router.get("v1/contracts/open", open_contracts, "open contracts");
        router.get("v1/contracts/users/done", done_contracts, "done contracts");
        router.get(
            "v1/contracts/admin/approved",
            admin_contracts,
            "contracts approved by admin",
        );
    }
}

struct CurrencyService;

impl Service for CurrencyService {
    fn service_name(&self) -> &'static str {
        "cryptocurrency"
    }

    fn service_id(&self) -> u16 {
        SERVICE_ID
    }

    fn tx_from_raw(&self, raw: RawTransaction) -> Result<Box<Transaction>, encoding::Error> {

        let trans: Box<Transaction> = match raw.message_type() {
            TX_CREATE_WALLET_ID => Box::new(TxCreateWallet::from_raw(raw)?),
            TX_CREATE_TASK_ID => Box::new(TxCreateTask::from_raw(raw)?),
            TX_CLOSE_TASK_ID => Box::new(TxCloseTask::from_raw(raw)?),
            TX_ASSIGN_TASK_ID => Box::new(TxAssignTask::from_raw(raw)?),
            TX_SUBMIT_SOLUTION_ID => Box::new(TxSubmitSolution::from_raw(raw)?),
            TX_ADMIN_EXAMINE_SOLUTION_ID => Box::new(TxAdminExamineSolution::from_raw(raw)?),
            TX_ACCEPT_SCHOLARSHIP_ID => Box::new(TxAcceptScholarship::from_raw(raw)?),
            _ => {
                return Err(encoding::Error::IncorrectMessageType {
                    message_type: raw.message_type(),
                });
            }
        };
        Ok(trans)
    }

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

// --------------------------------------------------- //


// -------------   Request and stuff   --------------- //


// --------------------------------------------------- //


fn main() {
    exonum::helpers::init_logger().unwrap();


    let database_options = LevelDBOptions {
        create_if_missing: true,
        error_if_exists: false,
        ..Default::default()
    };

    // Current state database
    //TODO: ERROR HANDLING
    let db = LevelDB::open(format!("{}/db", STORAGE_PATH), database_options).unwrap();

    let services: Vec<Box<Service>> = vec![Box::new(CurrencyService)];

    // Vlockchain initialisation
    let blockchain = Blockchain::new(Box::new(db), services);


    //---------------------------------------

    fn get_file_contents(path: &Path) -> String {
        let mut f = File::open(path).unwrap();
        let mut c = String::new();
        f.read_to_string(&mut c).unwrap();
        c
    }


    let node_keys_buf = get_file_contents(Path::new("keys1.keys"));
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


    //--------------------------------------

    let consensus_config = ConsensusConfig {
        txs_block_limit: 1,
        ..Default::default()
    };

    // Root block of the blockchain
    let genesis = GenesisConfig::new_with_consensus(consensus_config, validator_keys.into_iter());


    // External port -- for api interactions
    let api_adress = "0.0.0.0:1488".parse().unwrap();
    let api_adress2 = "0.0.0.0:1489".parse().unwrap();

    let api_cfg = NodeApiConfig {
        public_api_address: Some(api_adress),
        private_api_address: Some(api_adress2),
        enable_blockchain_explorer: true,
        ..Default::default()
    };

    // Internal port -- for node-to-node interactions
    let peer_adress = "0.0.0.0:2069".parse().unwrap();
    let test_peer = "1.2.3.4:2069".parse().unwrap();

    // Complete node configuration
    let node_cfg = NodeConfig {
        listen_address: peer_adress,
        peers: vec![test_peer],
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

    // Final setup
    let mut node = Node::new(blockchain, node_cfg);
    node.run().unwrap();
}
