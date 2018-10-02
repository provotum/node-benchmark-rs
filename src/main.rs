//! Compiles only with nightly builds of rust
//! ```
//! rustup run nightly cargo build --release
//! ``
//!
//! INFO  node_benchmark_rs > Size of clique before adding: 1240741
//! INFO  node_benchmark_rs > Current memory usage for CliqueProtocol containing 10 transactions is: 13734479 bytes / 13734 KBytes
//! INFO  node_benchmark_rs > Current memory usage for CliqueProtocol containing 100 transactions is: 132052349 bytes / 132052 KBytes
//! INFO  node_benchmark_rs > Current memory usage for CliqueProtocol containing 1000 transactions is: 1897945049 bytes / 1897945 KBytes
//! INFO  node_benchmark_rs > Total memory usage for CliqueProtocol containing 10000 transactions is: 77813950000 bytes / 77 813 950 KBytes

#![feature(alloc_system, global_allocator, allocator_api)]
extern crate alloc_system;

use alloc_system::System;

#[global_allocator]
static A: System = System;

extern crate node_rs;
extern crate crypto_rs;
extern crate generator_rs;
extern crate num;
extern crate env_logger;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;

extern crate bincode;
#[macro_use]
extern crate serde_derive;
extern crate serde;

use std::net::SocketAddr;
use std::vec::Vec;

use env_logger::Target;

use num::BigInt;
use num::One;
use num::Zero;

use crypto_rs::arithmetic::mod_int::ModInt;
use crypto_rs::arithmetic::mod_int::From;
use crypto_rs::el_gamal::encryption::{encrypt, PublicKey};
use crypto_rs::el_gamal::membership_proof::MembershipProof;
use crypto_rs::cai::uciv::{ImageSet, PreImageSet, CaiProof};

use node_rs::protocol::clique::CliqueProtocol;
use node_rs::config::genesis::{CliqueConfig, Genesis};
use node_rs::chain::transaction::Transaction;
use node_rs::p2p::codec::Message;
use node_rs::protocol::clique::ProtocolHandler;

use generator_rs::generator::{Generator};

fn main() {
    // init logger
    pretty_env_logger::formatted_builder().unwrap()
        //let's just set some random stuff.. for more see
        //https://docs.rs/env_logger/0.5.0-rc.1/env_logger/struct.Builder.html
        .target(Target::Stdout)
        .parse("node_benchmark_rs=trace")
        .init();

    let fake_sealer: SocketAddr = "127.0.0.1:9123".parse().unwrap();
    let sealers: Vec<SocketAddr> = vec![fake_sealer.clone()];

    let public_key: PublicKey = Generator::generate_keys().1;
    let number_voters = 10000;
    let number_voting_options = 2;
    trace!("generate uciv info...");
    let uciv = Generator::generate_uciv(number_voters, number_voting_options, public_key.clone());
    trace!("done.");

    let voting_options: Vec<ModInt> = vec![
        ModInt::from_value(BigInt::one()),
        ModInt::from_value(BigInt::zero())
    ];

    let genesis = Genesis {
        version: "0.0.0".to_string(),
        clique: CliqueConfig {
            block_period: 15,
            signer_limit: 0,
        },
        sealer: sealers,
        public_key: public_key.clone(),
        public_uciv: uciv.public_uciv.clone(),
    };

    let mut clique = CliqueProtocol::new(fake_sealer.clone(), genesis);
    let mut total_bytes_used: usize = 0;
    info!("Size of clique before adding: {}", bincode::serialize(&clique).unwrap().len());

    for voter_idx in 0..number_voters {
        let vote = ModInt::from_value(BigInt::from(1));
        let encrypted_vote = encrypt(&public_key.clone(), vote.clone());
        let membership_proof = MembershipProof::new(public_key.clone(), vote.clone(), encrypted_vote.clone(), voting_options.clone());

        let pre_image_set: PreImageSet = uciv.private_uciv.get(voter_idx as usize).unwrap().clone();
        let image_set: ImageSet = uciv.public_uciv.get(voter_idx as usize).unwrap().clone();

        let chosen_vote_index = voting_options.iter().position(|e| e.clone() == vote.clone()).unwrap();

        let cai_proof = CaiProof::new(public_key.clone(), encrypted_vote.clone(), pre_image_set, image_set, chosen_vote_index, voting_options.clone());

        let trx = Transaction {
            voter_idx: voter_idx as usize,
            cipher_text: encrypted_vote,
            membership_proof,
            cai_proof,
        };

        clique.handle(Message::TransactionPayload(trx));
        let bytes_used = bincode::serialize(&clique).unwrap().len();
        total_bytes_used = total_bytes_used + bytes_used;

        if voter_idx == 10 || voter_idx == 100 || voter_idx == 1000 || voter_idx == 10000 {
            info!("Current memory usage for CliqueProtocol containing {} transactions is: {} bytes / {} KBytes", voter_idx, total_bytes_used, total_bytes_used / 1000);
        }
    }

    info!("Total memory usage for CliqueProtocol containing {} transactions is: {} bytes / {} KBytes", number_voters, total_bytes_used, total_bytes_used / 1000);
}
