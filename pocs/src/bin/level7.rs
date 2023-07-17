use std::{env, str::FromStr};
use solana_sdk::account::Account;
use solana_sdk::signature::Keypair;
use solana_program::{bpf_loader, pubkey::Pubkey};
use solana_program::instruction::{AccountMeta, Instruction};
use poc_framework::{
    solana_sdk::signer::Signer, Environment, LocalEnvironment, PrintableTransaction,
};

// 3rd party dependencies
use actix_web::{web, App, HttpServer, HttpResponse, http::{header::{ContentType}, StatusCode}};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use aes::Aes128;
use vmprotect::protected;
use vmprotect_sys;
use std::io::prelude::*;
use figlet_rs::FIGfont;
use std::path::Path;
use ini::Ini;
use std::io;
use serde;
use hex;

// VMP mark for authenticate_license
const MARKER_NAME: [i8; 21] = [97i8, 117i8, 116i8, 104i8, 101i8, 110i8, 116i8, 105i8, 99i8, 97i8, 116i8, 101i8, 95i8, 108i8, 105i8, 99i8, 101i8, 110i8, 115i8, 101i8, 0i8,];
// Load exchange art binary contents
pub const EXCHANGE_ART_BINARY: &[u8] = include_bytes!("programs/exchange_art.so");
pub const TOKEN_MANAGER_BINARY: &[u8] = include_bytes!("programs/token_manager.so");
// Decryption key for payload
static PAYLOAD_KEY: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; //clean

// create an alias for convenience
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

#[derive(serde::Serialize, serde::Deserialize)]
struct AuthResponse {
    success: bool,
    domain: String,
    secret: String,
    access_token: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SolverResponse {
    hmac: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SolverData {
    saleType:                 i32,

	buyer: String,
	masterMintKey: String,
	masterEditionPda: String,
	masterMetadataPda: String,
	seller: String,
	saleStateAccount: String,
	newEditionMetadataPda: String,
	newEditionPda: String,
	newEditionMintKey: String,
	walletMintingState: String,
	editionMarkPda: String,
	depositAccountAddress: String,
	newEditionDepositAccount: String,
	newEditionDepositAuthority: String,
	exchangeFeeRecipient: String,
	exchgMasterEditionDepositAuthority: String,
	cardinalManager: String,
	cardinalMintCounter: String,
	tokenProgram: String,
	tokenMetadataProgram: String,
	cardinalTokenManagerProgram: String,
	systemProgram: String,
	rent: String,
	instructions: String,
    buyerTokenAccount: String,
    creatorAddresses:         Vec<String>,

    mintData:         String,
    tokenMintData:    String,
    tokenAccountData: String,
    masterMintKeyData:     String,
    masterEditionPdaData:  String,
    masterMetadataPdaData: String,
    sellerData:            String,
    saleStateAccountData:  String,
    depositAccountData:    String,
    buyerTokenAccountData: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SolverPayload {
    challenge: String
}

pub fn decrypt_aes128(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut encrypted_data = data.clone().to_owned();
    let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();
    cipher.decrypt(&mut encrypted_data).unwrap().to_vec()
}

fn wait_for_key_press() {
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    // We want the cursor to stay at the end of the line, so we print without a newline and flush manually.
    write!(stdout, "Press enter to continue...").unwrap();
    stdout.flush().unwrap();

    // Read a single byte and discard
    let _ = stdin.read(&mut [0u8]).unwrap();
}


fn authenticate_license(conf: Ini) {
    //clean
}

async fn generate_hmac(item: web::Json<SolverPayload>) -> HttpResponse {
    // Decode encrypted hex string
    let ciphertext = hex::decode(
        &item.challenge
    ).unwrap();

    // Separate iv from encrypted data
    let iv = &ciphertext[0..16];
    let data = &ciphertext[16..];

    // Decrypt data and convert result to string
    let data_decrypted = decrypt_aes128(&PAYLOAD_KEY, &iv, &data);
    let data_string = std::str::from_utf8(&data_decrypted).unwrap().to_string();

    // Parse json string into data struct
    let payload_data: SolverData = serde_json::from_str(&data_string).unwrap();

    let hmac_code = setup(payload_data);

    //let encoded_hmac = hex::encode(hmac_code);
    //println!("HMAC from return {:?}", &encoded_hmac);

    let obj = SolverResponse {
        hmac: hmac_code,
    };
    
    let serialized_obj = serde_json::to_string(&obj).unwrap();

    HttpResponse::Ok()
        .content_type(ContentType::json())
        .body(serialized_obj)
}

#[actix_web::main] // or #[tokio::main]
pub async fn main() -> std::io::Result<()> {

    println!("* Solver listening on port :8172 (Press CTRL+C to quit)");
    HttpServer::new(|| {
        App::new()
        .service(web::resource("/api/solve").route(web::post().to(generate_hmac)))
    })
    .bind(("127.0.0.1", 8172))?
    .run()
    .await
}


fn setup(payload: SolverData) -> [u8; 32] {
    let exchange_art_program = Pubkey::from_str("EXBuYPNgBUXMTsjCbezENRUtFQzjUNZxvPGTd11Pznk5").unwrap();
    let token_manager_program = Pubkey::from_str("mgr99QFMYByTqGPWmNqunV7vBLmWWXdSrHUfV8Jf3JM").unwrap();

	let buyer = Keypair::from_base58_string(&payload.buyer);
	let masterMintKey = Pubkey::from_str(&payload.masterMintKey).unwrap();
	let masterEditionPda = Pubkey::from_str(&payload.masterEditionPda).unwrap();
	let masterMetadataPda = Pubkey::from_str(&payload.masterMetadataPda).unwrap();
	let seller = Pubkey::from_str(&payload.seller).unwrap();
	let saleStateAccount = Pubkey::from_str(&payload.saleStateAccount).unwrap();
	let newEditionMetadataPda = Pubkey::from_str(&payload.newEditionMetadataPda).unwrap();
	let newEditionPda = Pubkey::from_str(&payload.newEditionPda).unwrap();
	let newEditionMintKey = Keypair::from_base58_string(&payload.newEditionMintKey);
	let walletMintingState = Pubkey::from_str(&payload.walletMintingState).unwrap();
	let editionMarkPda = Pubkey::from_str(&payload.editionMarkPda).unwrap();
	let depositAccountAddress = Pubkey::from_str(&payload.depositAccountAddress).unwrap();
	let newEditionDepositAccount = Pubkey::from_str(&payload.newEditionDepositAccount).unwrap();
	let newEditionDepositAuthority = Pubkey::from_str(&payload.newEditionDepositAuthority).unwrap();
	let exchangeFeeRecipient = Pubkey::from_str(&payload.exchangeFeeRecipient).unwrap();
	let exchgMasterEditionDepositAuthority = Pubkey::from_str(&payload.exchgMasterEditionDepositAuthority).unwrap();
	let cardinalManager = Pubkey::from_str(&payload.cardinalManager).unwrap();
	let cardinalMintCounter = Pubkey::from_str(&payload.cardinalMintCounter).unwrap();
	let tokenProgram = Pubkey::from_str(&payload.tokenProgram).unwrap();
	let tokenMetadataProgram = Pubkey::from_str(&payload.tokenMetadataProgram).unwrap();
	let cardinalTokenManagerProgram = Pubkey::from_str(&payload.cardinalTokenManagerProgram).unwrap();
	let systemProgram = Pubkey::from_str(&payload.systemProgram).unwrap();
	let rent = Pubkey::from_str(&payload.rent).unwrap();
	let instructions = Pubkey::from_str(&payload.instructions).unwrap();
	let buyerTokenAccount = Pubkey::from_str(&payload.buyerTokenAccount).unwrap();

    let mut account_info = 
        if payload.saleType == 1 {
           //fixed
            vec![
                AccountMeta::new(buyer.pubkey(), true),
                AccountMeta::new_readonly(masterMintKey, false),
                AccountMeta::new(masterEditionPda, false),
                AccountMeta::new_readonly(masterMetadataPda, false),
                AccountMeta::new_readonly(seller, false),
                AccountMeta::new(saleStateAccount, false),
                AccountMeta::new(newEditionMetadataPda, false),
                AccountMeta::new(newEditionPda, false),
                AccountMeta::new(newEditionMintKey.pubkey(), true),
                AccountMeta::new(walletMintingState, false),
                AccountMeta::new(editionMarkPda, false),
                AccountMeta::new(depositAccountAddress, false),
                AccountMeta::new(newEditionDepositAccount, false),
                AccountMeta::new(newEditionDepositAuthority, false),
                AccountMeta::new(exchangeFeeRecipient, false),
                AccountMeta::new_readonly(exchgMasterEditionDepositAuthority, false),
                AccountMeta::new(cardinalManager, false),
                AccountMeta::new(cardinalMintCounter, false),
                AccountMeta::new_readonly(tokenProgram, false),
                AccountMeta::new_readonly(tokenMetadataProgram, false),
                AccountMeta::new_readonly(cardinalTokenManagerProgram, false),
                AccountMeta::new_readonly(systemProgram, false),
                AccountMeta::new_readonly(rent, false),
                AccountMeta::new_readonly(instructions, false)
            ]
        } else{ 
            //increment
            vec![
                AccountMeta::new(buyer.pubkey(), true),
                AccountMeta::new_readonly(masterMintKey, false),
                AccountMeta::new(masterEditionPda, false),
                AccountMeta::new_readonly(masterMetadataPda, false),
                AccountMeta::new_readonly(seller, false),
                AccountMeta::new(saleStateAccount, false),
                AccountMeta::new(newEditionMetadataPda, false),
                AccountMeta::new(newEditionPda, false),
                AccountMeta::new(newEditionMintKey.pubkey(), true),
                AccountMeta::new(editionMarkPda, false),
                AccountMeta::new(depositAccountAddress, false),
                AccountMeta::new(newEditionDepositAccount, false),
                AccountMeta::new(exchangeFeeRecipient, false),
                AccountMeta::new_readonly(exchgMasterEditionDepositAuthority, false),
                AccountMeta::new_readonly(tokenProgram, false),
                AccountMeta::new_readonly(tokenMetadataProgram, false),
                AccountMeta::new_readonly(systemProgram, false),
                AccountMeta::new_readonly(rent, false),
                AccountMeta::new_readonly(instructions, false)]
        };
    
    for creator in &payload.creatorAddresses {
        let tmp = Pubkey::from_str(&creator).unwrap();
        account_info.push(AccountMeta::new(tmp, false));
    }

    let decoded_data = hex::decode(&payload.mintData).expect("Decoding failed");
    let decoded_token_data = hex::decode(&payload.tokenMintData).expect("Decoding failed");
    let decoded_token_account_data = hex::decode(&payload.tokenAccountData).expect("Decoding failed");
    let decoded_master_mint_data = hex::decode(&payload.masterMintKeyData).expect("Decoding failed");
    let decoded_master_edition_data = hex::decode(&payload.masterEditionPdaData).expect("Decoding failed");
    let decoded_master_metadata_data = hex::decode(&payload.masterMetadataPdaData).expect("Decoding failed");
    let seller_data = hex::decode(&payload.sellerData).expect("Decoding failed");
    let decoded_sale_state_data = hex::decode(&payload.saleStateAccountData).expect("Decoding failed");
    let decoded_deposit_account_data = hex::decode(&payload.depositAccountData).expect("Decoding failed");
    let decoded_buyer_token_data = hex::decode(&payload.buyerTokenAccountData).expect("Decoding failed");

    let mut env = 
        if payload.saleType == 1 {
            LocalEnvironment::builder()
            .add_account_with_data(exchange_art_program, bpf_loader::ID, EXCHANGE_ART_BINARY, true)
            .add_account_with_data(token_manager_program, bpf_loader::ID, TOKEN_MANAGER_BINARY, true)

            .add_account(buyer.pubkey(), Account {lamports: 66842534800000, data: vec![], owner: systemProgram, executable: false, rent_epoch: 348})
            .add_account(masterMintKey, Account {lamports: 668425348, data: decoded_master_mint_data, owner: tokenProgram, executable: false, rent_epoch: 348})
            .add_account(masterEditionPda, Account {lamports: 668425348, data: decoded_master_edition_data, owner: tokenMetadataProgram, executable: false, rent_epoch: 348})
            .add_account(masterMetadataPda, Account {lamports: 668425348, data: decoded_master_metadata_data, owner: tokenMetadataProgram, executable: false, rent_epoch: 348})
            .add_account(seller, Account {lamports: 668425348, data: seller_data, owner: systemProgram, executable: false, rent_epoch: 348})
            .add_account(saleStateAccount, Account {lamports: 668425348, data: decoded_sale_state_data, owner: exchange_art_program, executable: false, rent_epoch: 348})
            .add_account(newEditionMetadataPda, Account {lamports: 20392800000, data: vec![4, 33, 135, 7, 128, 169, 120, 25, 11, 8, 178, 91, 219, 13, 89, 182, 243, 76, 178, 149, 214, 166, 129, 70, 58, 76, 15, 145, 65, 42, 6, 182, 248, 129, 223, 139, 221, 237, 167, 128, 212, 83, 99, 120, 223, 202, 196, 105, 221, 192, 67, 198, 200, 26, 14, 210, 143, 50, 62, 52, 25, 57, 81, 15, 92, 32, 0, 0, 0, 231, 139, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 200, 0, 0, 0, 104, 116, 116, 112, 115, 58, 47, 47, 97, 114, 119, 101, 97, 118, 101, 46, 110, 101, 116, 47, 90, 68, 108, 85, 83, 68, 67, 78, 51, 83, 113, 66, 101, 104, 116, 77, 83, 67, 87, 117, 50, 52, 108, 122, 88, 79, 101, 112, 48, 52, 116, 101, 90, 119, 55, 104, 122, 114, 53, 53, 107, 97, 81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 244, 1, 1, 1, 0, 0, 0, 33, 135, 7, 128, 169, 120, 25, 11, 8, 178, 91, 219, 13, 89, 182, 243, 76, 178, 149, 214, 166, 129, 70, 58, 76, 15, 145, 65, 42, 6, 182, 248, 1, 100, 1, 0, 1, 255, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], owner: tokenMetadataProgram, executable: false, rent_epoch: 348})
            .add_account(newEditionPda, Account {lamports: 20392800000, data: vec![1, 169, 46, 68, 104, 83, 171, 106, 239, 168, 98, 152, 84, 167, 151, 64, 58, 42, 107, 144, 126, 125, 100, 142, 192, 17, 116, 220, 141, 204, 51, 156, 48, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], owner: tokenMetadataProgram, executable: false, rent_epoch: 347})
            .add_account(newEditionMintKey.pubkey(), Account {lamports: 668425348, data: decoded_token_data, owner: tokenProgram, executable: false, rent_epoch: 350})
            .add_account(walletMintingState, Account {lamports: 668425348, data: vec![191, 97, 167, 235, 218, 58, 70, 77, 0, 0, 0, 0, 0, 0, 0, 0], owner: exchange_art_program, executable: false, rent_epoch: 348})
            .add_account(editionMarkPda, Account {lamports: 20392800000, data: vec![7, 127, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], owner: tokenMetadataProgram, executable: false, rent_epoch: 348})
            .add_account(depositAccountAddress, Account {lamports: 20392800000, data: decoded_deposit_account_data, owner: tokenProgram, executable: false, rent_epoch: 348})
            .add_account(newEditionDepositAccount, Account {lamports: 20392800000, data: decoded_token_account_data, owner: tokenProgram, executable: false, rent_epoch: 347})
            .add_account(newEditionDepositAuthority, Account {lamports: 20392800000,  data: vec![], owner: systemProgram, executable: false, rent_epoch: 347})
            .add_account(exchangeFeeRecipient, Account {lamports: 172016150445, data: vec![], owner: systemProgram, executable: false, rent_epoch: 361})
            .add_account(exchgMasterEditionDepositAuthority, Account {lamports: 172016150445, data: vec![], owner: systemProgram, executable: false, rent_epoch: 361})
            //.add_account(cardinalManager, Account {lamports: 2039280, data: decoded_token_account_data, owner: tokenProgram, executable: false, rent_epoch: 347})
            //.add_account(cardinalMintCounter, Account {lamports: 2039280, data: decoded_token_account_data, owner: tokenProgram, executable: false, rent_epoch: 347})
            .add_account(buyerTokenAccount, Account {lamports: 203928000000, data: decoded_buyer_token_data, owner: tokenProgram, executable: false, rent_epoch: 347})

            .build()
        } else {
            LocalEnvironment::builder()
            .add_account_with_data(exchange_art_program, bpf_loader::ID, EXCHANGE_ART_BINARY, true)
            .add_account_with_data(token_manager_program, bpf_loader::ID, TOKEN_MANAGER_BINARY, true)

            .add_account(masterMintKey, Account {lamports: 668425348, data: decoded_master_mint_data, owner: tokenProgram, executable: false, rent_epoch: 348})
            .add_account(masterEditionPda, Account {lamports: 668425348, data: decoded_master_edition_data, owner: tokenMetadataProgram, executable: false, rent_epoch: 348})
            .add_account(masterMetadataPda, Account {lamports: 668425348, data: decoded_master_metadata_data, owner: tokenMetadataProgram, executable: false, rent_epoch: 348})
            .add_account(seller, Account {lamports: 668425348, data: seller_data, owner: systemProgram, executable: false, rent_epoch: 348})
            .add_account(saleStateAccount, Account {lamports: 668425348, data: decoded_sale_state_data, owner: exchange_art_program, executable: false, rent_epoch: 348})
            .add_account(depositAccountAddress, Account {lamports: 668425348, data: decoded_deposit_account_data, owner: tokenProgram, executable: false, rent_epoch: 348})

            .add_account(exchangeFeeRecipient, Account {lamports: 668425348, data: vec![], owner: systemProgram, executable: false, rent_epoch: 348})
            //.add_account(walletMintingState, Account {lamports: 668425348, data: vec![], owner: exchange_art_program, executable: false, rent_epoch: 348})
            .add_account(newEditionMintKey.pubkey(), Account {lamports: 668425348, data: decoded_token_data, owner: tokenProgram, executable: false, rent_epoch: 348})
            .add_account(buyer.pubkey(), Account {lamports: 668425348, data: vec![], owner: systemProgram, executable: false, rent_epoch: 348})
            .add_account(newEditionMetadataPda, Account {lamports: 5616720, data: vec![4, 33, 135, 7, 128, 169, 120, 25, 11, 8, 178, 91, 219, 13, 89, 182, 243, 76, 178, 149, 214, 166, 129, 70, 58, 76, 15, 145, 65, 42, 6, 182, 248, 129, 223, 139, 221, 237, 167, 128, 212, 83, 99, 120, 223, 202, 196, 105, 221, 192, 67, 198, 200, 26, 14, 210, 143, 50, 62, 52, 25, 57, 81, 15, 92, 32, 0, 0, 0, 231, 139, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 200, 0, 0, 0, 104, 116, 116, 112, 115, 58, 47, 47, 97, 114, 119, 101, 97, 118, 101, 46, 110, 101, 116, 47, 90, 68, 108, 85, 83, 68, 67, 78, 51, 83, 113, 66, 101, 104, 116, 77, 83, 67, 87, 117, 50, 52, 108, 122, 88, 79, 101, 112, 48, 52, 116, 101, 90, 119, 55, 104, 122, 114, 53, 53, 107, 97, 81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 244, 1, 1, 1, 0, 0, 0, 33, 135, 7, 128, 169, 120, 25, 11, 8, 178, 91, 219, 13, 89, 182, 243, 76, 178, 149, 214, 166, 129, 70, 58, 76, 15, 145, 65, 42, 6, 182, 248, 1, 100, 1, 0, 1, 255, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], owner: tokenMetadataProgram, executable: false, rent_epoch: 348})
            .add_account(newEditionPda, Account {lamports: 2568240, data: vec![1, 169, 46, 68, 104, 83, 171, 106, 239, 168, 98, 152, 84, 167, 151, 64, 58, 42, 107, 144, 126, 125, 100, 142, 192, 17, 116, 220, 141, 204, 51, 156, 48, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], owner: tokenMetadataProgram, executable: false, rent_epoch: 347})
            .add_account(editionMarkPda, Account {lamports: 1113600, data: vec![7, 127, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], owner: tokenMetadataProgram, executable: false, rent_epoch: 348})
            .add_account(newEditionDepositAccount, Account {lamports: 2039280, data: decoded_token_account_data, owner: tokenProgram, executable: false, rent_epoch: 347})
            .build()
        };

    env.execute_as_transaction(
        &[Instruction {
            program_id: exchange_art_program,
            accounts: account_info,
            data: decoded_data,
        }],
        &[&buyer,&newEditionMintKey],
    );

    return env.result.result;
}