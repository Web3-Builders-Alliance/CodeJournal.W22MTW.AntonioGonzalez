/*
All the imported values are in https://github.com/Web3-Builders-Alliance/CodeJournal.W22MTW.AntonioGonzalez/blob/main/1/reviewed/contract.rs
The new ones are
 * entry_point - Macro that generates the boilerplate required to call into 
                 the contract-specific logic from the entry-points to the Wasm module.
 * BankMsg - Enum with two structs: 
    * Send - Contains to_address y amount, so you can send the assets from the contract to the user.
    * Burn - Burns an amount of assets the contract holds
 * Coin - Structure with denom and amount, so you can say the name of the coin and how much represents the variable
*/
use cosmwasm_std::{
    entry_point, to_binary, Addr, BankMsg, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Response,
    StdResult,
};

// Structs and Enums from other parts of the contract
use crate::error::ContractError;
use crate::msg::{ArbiterResponse, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CONFIG};
use cw2::set_contract_version;

// Version info, for migration info
const CONTRACT_NAME: &str = "crates.io:cw20-merkle-airdrop";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    /*
    In the config we set
        * arbiter (the addr who instantiates the contract and is able to approve sending assets)
        * recipient (the addr that will receive the assets)
        * source (*)
        * expiration (in case it's given, the escrow will have a time limit)
    */
    let config = Config {
        arbiter: deps.api.addr_validate(&msg.arbiter)?,
        recipient: deps.api.addr_validate(&msg.recipient)?,
        source: info.sender,
        expiration: msg.expiration,
    };


    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    /*
     * If the expiration in the msg is older than the current time, it returns 
     * a contract error to instantiate
     */
    if let Some(expiration) = msg.expiration {
        if expiration.is_expired(&env.block) {
            return Err(ContractError::Expired { expiration });
        }
    }
    /*
    The config saves the config that was created and we return an ok response
     */
    CONFIG.save(deps.storage, &config)?;
    Ok(Response::default())
}


#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    /*
    Execute messages that are available:
        * execute_approve: sends quantity of assets to the contract (depends on if the variable is settled)
        * execute_refund: If the contract has expired, you can send all your assets
    */
    match msg {
        ExecuteMsg::Approve { quantity } => execute_approve(deps, env, info, quantity),
        ExecuteMsg::Refund {} => execute_refund(deps, env, info),
    }
}

fn execute_approve(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    quantity: Option<Vec<Coin>>,
) -> Result<Response, ContractError> {
    // We load the config to have the addresses we require to proceed
    let config = CONFIG.load(deps.storage)?;
    // If the sender of the execute msg is not the arbiter, it can't approve sending any asset.
    if info.sender != config.arbiter {
        // error un error.rs line 10 (not much to mention about it)
        return Err(ContractError::Unauthorized {});
    }

    // throws error if the contract is expired and doesn't approve anything
    // this error can be seen in error.rs line 14.
    if let Some(expiration) = config.expiration {
        // expiration module contains is_expired impl that is called to check if
        // &env.block >= current height. Is a bool.
        if expiration.is_expired(&env.block) {
            return Err(ContractError::Expired { expiration });
        }
    }

    /*
    First we check if there is some quantity in the msg we're sending, and if 
    there is something, we define the amount as that. Otherwise we query for the
    amount the contract holds, and we just define that amount as the one to send
    to finally send an Ok response with a send_tokens msg.
    */
    let amount = if let Some(quantity) = quantity {
        quantity
    } else {
        deps.querier.query_all_balances(&env.contract.address)?
    };
    // Here we send the tokens and we add the address that will receive the assets 
    // as recipient. Also since it's the recipient the one that is receiving, 
    // we set the action as an "approve"
    Ok(send_tokens(config.recipient, amount, "approve"))
}

fn execute_refund(deps: DepsMut, env: Env, _info: MessageInfo) -> Result<Response, ContractError> {
    // We load the config in the contract because we'll get the source address to refund in case
    // we execute all this function correctly
    let config = CONFIG.load(deps.storage)?;
    // We verify if the expiration isn't reached. If it isn't expired, you can't refund the assets yet
    if let Some(expiration) = config.expiration {
        if !expiration.is_expired(&env.block) {
            return Err(ContractError::NotExpired {});
        }
    } else {
        return Err(ContractError::NotExpired {});
    }

    // If it is, we get all the balance of the contract to send all the tokens to the source that
    // originally sent the assets (we get the address from the config we loaded at the beginning)
    let balance = deps.querier.query_all_balances(&env.contract.address)?;
    Ok(send_tokens(config.source, balance, "refund"))
}

// Function to send tokens. The action will depend on if it's an approve or a refund.
// If it's a refund, the funds will be returned to the source. 
// If it's an approve, the funds will be sent to the recipient. 
fn send_tokens(to_address: Addr, amount: Vec<Coin>, action: &str) -> Response {
    Response::new()
        .add_message(BankMsg::Send {
            to_address: to_address.clone().into(), // address (included in params)
            amount, // adding the amount sent (included in params)
        })
        // Here we just add some info to make it understandable in the response of the function
        .add_attribute("action", action)
        .add_attribute("to", to_address)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        /* The only query message included in the contract It calls the function
         below this query (query_arbiter)

         Some queries to improve this contract would be 
           - querying amount already approved to the recipient
           - querying time until contract gets expired
           - Amount in the contract
        */
        QueryMsg::Arbiter {} => to_binary(&query_arbiter(deps)?),
    }
}

/*
Queries the arbiter from the contract by loading the config of the contract, 
calling this variable and then returns as a response the arbiter address 
in an Ok response.
*/
fn query_arbiter(deps: Deps) -> StdResult<ArbiterResponse> {
    let config = CONFIG.load(deps.storage)?;
    let addr = config.arbiter;
    Ok(ArbiterResponse { arbiter: addr })
}

// Here we start the tests of the contract
#[cfg(test)]
mod tests {
    // We invoke all the functions outside the tests module
    use super::*;
    // We call all the things required to invoke the mock chain
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    /* We invoke 
         - coins: Struct with amount and denom
         - CosmosMsg: Struct that lets you make different commands with your assets
         - Timestamp: Struct with functions about time in seconds, nanosecs, minutes, etc
     */ 
    use cosmwasm_std::{coins, CosmosMsg, Timestamp};
    // Expiration struct for comparing the time with the time of expiration of the contract
    use cw_utils::Expiration;

    // We create the instantiate message.
    fn init_msg_expire_by_height(expiration: Option<Expiration>) -> InstantiateMsg {
        InstantiateMsg {
            arbiter: String::from("verifies"),
            recipient: String::from("benefits"),
            expiration,
        }
    }
    // First test
    #[test]
    fn proper_initialization() {
        // Creating mock state of chain
        let mut deps = mock_dependencies();

        // Instantiate message in the line 202. We only required to add the block instantiation dies
        let msg = init_msg_expire_by_height(Some(Expiration::AtHeight(1000)));
        // We set a mock state to work with the blocks 
        let mut env = mock_env();
        // Setting the block height and the time
        env.block.height = 876;
        env.block.time = Timestamp::from_seconds(0);
        // Mock info for the instantiate command. The two things to send are the sender and the funds
        let info = mock_info("creator", &coins(1000, "earth"));

        // Finally we instantiate the contract with the information previously added
        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();
        // We just assert if the response has 0 messages (it shouldn't have since we didn't define any)
        assert_eq!(0, res.messages.len());

        // If it worked all, we query the state of the contract config to check the addressses involved 
        // and the time the contract expires to assert if it's how it should be.
        let state = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(
            state,
            Config {
                arbiter: Addr::unchecked("verifies"),
                recipient: Addr::unchecked("benefits"),
                source: Addr::unchecked("creator"),
                expiration: Some(Expiration::AtHeight(1000))
            }
        );
    }
    
    #[test]
    fn cannot_initialize_expired() {
        // Again mock dependency an instantiate message generator with height expiration 1000.
        // and the mock environment with height and time to later compare it.
        let mut deps = mock_dependencies();

        // Our init message says height 1000 
        let msg = init_msg_expire_by_height(Some(Expiration::AtHeight(1000)));
        let mut env = mock_env();
        // And the block we're setting is 1001, so should break
        env.block.height = 1001;
        env.block.time = Timestamp::from_seconds(0);
        // Generating the info of the funds
        let info = mock_info("creator", &coins(1000, "earth"));
        // Instantiating contract
        let res = instantiate(deps.as_mut(), env, info, msg);
        // We just check that it actually broke and sent the correct error (Expired)
        match res.unwrap_err() {
            ContractError::Expired { .. } => {}
            e => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    fn init_and_query() {
        let mut deps = mock_dependencies();
        // We generate the addresses we need for the message
        let arbiter = Addr::unchecked("arbiters");
        let recipient = Addr::unchecked("receives");
        let creator = Addr::unchecked("creates");
        // We include all the info for the Instantiate msg
        let msg = InstantiateMsg {
            arbiter: arbiter.clone().into(),
            recipient: recipient.into(),
            expiration: None,
        };
        let mut env = mock_env();
        // We add any block height (it doesn't matter since we don't add an 
        // expiration date)
        env.block.height = 876;
        env.block.time = Timestamp::from_seconds(0);
        // We don't add anything else
        let info = mock_info(creator.as_str(), &[]);
        // Instantiate
        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();
        // We get the response as something empty
        assert_eq!(0, res.messages.len());

        // And we query if the arbiter is actually the one we defined
        let query_response = query_arbiter(deps.as_ref()).unwrap();
        assert_eq!(query_response.arbiter, arbiter);
    }

    #[test]
    fn execute_approve() {
        let mut deps = mock_dependencies();

        // initialize the store
        let init_amount = coins(1000, "earth");
        // Instantiate msg at height 1000
        let msg = init_msg_expire_by_height(Some(Expiration::AtHeight(1000)));
        let mut env = mock_env();
        // We set a previous block than the one we're setting
        env.block.height = 876;
        env.block.time = Timestamp::from_seconds(0);
        // Mock info with the amount of tokens we'll send in the tx
        let info = mock_info("creator", &init_amount);
        // We get the contract address
        let contract_addr = env.clone().contract.address;
        // We instantiate
        let init_res = instantiate(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(0, init_res.messages.len());

        // We update the balance of the address
        deps.querier.update_balance(&contract_addr, init_amount);

        // We check the address 'beneficiary' can't execute the contract
        let msg = ExecuteMsg::Approve { quantity: None };
        let mut env = mock_env();
        env.block.height = 900;
        env.block.time = Timestamp::from_seconds(0);
        let info = mock_info("beneficiary", &[]);
        let execute_res = execute(deps.as_mut(), env, info, msg.clone());
        // And we verify the respective error 
        match execute_res.unwrap_err() {
            ContractError::Unauthorized { .. } => {}
            e => panic!("unexpected error: {:?}", e),
        }

        // Checking that in block 1100 we can't ask for the tokens if the 
        // Contract expired
        let mut env = mock_env();
        env.block.height = 1100;
        env.block.time = Timestamp::from_seconds(0);
        let info = mock_info("verifies", &[]);
        let execute_res = execute(deps.as_mut(), env, info, msg.clone());
        // And we get the respective error
        match execute_res.unwrap_err() {
            ContractError::Expired { .. } => {}
            e => panic!("unexpected error: {:?}", e),
        }

        // Here we check the 'verifies' address can send the assets before 
        // the expiration mark
        let mut env = mock_env();
        env.block.height = 999;
        env.block.time = Timestamp::from_seconds(0);
        let info = mock_info("verifies", &[]);
        let execute_res = execute(deps.as_mut(), env, info, msg).unwrap();
        // We verify after executing there is at least one message
        assert_eq!(1, execute_res.messages.len());
        let msg = execute_res.messages.get(0).expect("no message");
        // And the submsg is the CosmosMsg that sent the tokens to 'benefits' Addr.
        assert_eq!(
            msg.msg,
            CosmosMsg::Bank(BankMsg::Send {
                to_address: "benefits".into(),
                amount: coins(1000, "earth"),
            })
        );

        // partial release by verifier, before expiration
        let partial_msg = ExecuteMsg::Approve {
            quantity: Some(coins(500, "earth")),
        };
        let mut env = mock_env();
        env.block.height = 999;
        env.block.time = Timestamp::from_seconds(0);
        // We need 'verifies' address to send the msg
        let info = mock_info("verifies", &[]);
        let execute_res = execute(deps.as_mut(), env, info, partial_msg).unwrap();
        // We verify content and same procedure as before
        assert_eq!(1, execute_res.messages.len());
        let msg = execute_res.messages.get(0).expect("no message");
        assert_eq!(
            msg.msg,
            CosmosMsg::Bank(BankMsg::Send {
                to_address: "benefits".into(),
                amount: coins(500, "earth"),
            })
        );
    }

    #[test]
    fn handle_refund() {
        let mut deps = mock_dependencies();

        // initialize the store
        let init_amount = coins(1000, "earth");
        // Create the msg
        let msg = init_msg_expire_by_height(Some(Expiration::AtHeight(1000)));
        // Creating env
        let mut env = mock_env();
        env.block.height = 876;
        env.block.time = Timestamp::from_seconds(0);
        // Creating mock info.
        let info = mock_info("creator", &init_amount);
        let contract_addr = env.clone().contract.address;
        // Instantiate the msg with the previous vars defined
        let init_res = instantiate(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(0, init_res.messages.len());

        // balance from contract is updated given the amount.
        deps.querier.update_balance(&contract_addr, init_amount);

        // We'll try to refund and see an error because it's not expired yet
        let msg = ExecuteMsg::Refund {};
        // We define again the whole env
        let mut env = mock_env();
        env.block.height = 800;
        env.block.time = Timestamp::from_seconds(0);
        // And the MessageInfo would have any user to refund
        let info = mock_info("anybody", &[]);
        let execute_res = execute(deps.as_mut(), env, info, msg);
        // But will get a mistake because the expiration is at block 1000, not 800
        match execute_res.unwrap_err() {
            ContractError::NotExpired { .. } => {}
            e => panic!("unexpected error: {:?}", e),
        }

        // Checking expiration when block == expiration_block
        let msg = ExecuteMsg::Refund {};
        // New env
        let mut env = mock_env();
        env.block.height = 1000;
        env.block.time = Timestamp::from_seconds(0);
        // anybody as sender
        let info = mock_info("anybody", &[]);
        // Executing
        let execute_res = execute(deps.as_mut(), env, info, msg).unwrap();
        // Getting the output should contain 1 message
        assert_eq!(1, execute_res.messages.len());
        // We read the content
        let msg = execute_res.messages.get(0).expect("no message");
        // And verify there is a submsg that is the sending of the assets
        // to the creator
        assert_eq!(
            msg.msg,
            CosmosMsg::Bank(BankMsg::Send {
                to_address: "creator".into(),
                amount: coins(1000, "earth"),
            })
        );

        // And everyone can refund given the expiration
        let msg = ExecuteMsg::Refund {};
        // Remember expiration_block == 1000 and here we're making it 1001
        let mut env = mock_env();
        env.block.height = 1001;
        env.block.time = Timestamp::from_seconds(0);
        // Rest of procedure is as before
        let info = mock_info("anybody", &[]);
        let execute_res = execute(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(1, execute_res.messages.len());
        let msg = execute_res.messages.get(0).expect("no message");
        assert_eq!(
            msg.msg,
            CosmosMsg::Bank(BankMsg::Send {
                to_address: "creator".into(),
                amount: coins(1000, "earth"),
            })
        );
    }

    #[test]
    // Name of test speaks by itself
    fn handle_refund_no_expiration() {
        let mut deps = mock_dependencies();

        // initialize the store
        let init_amount = coins(1000, "earth");
        let msg = init_msg_expire_by_height(None);
        let mut env = mock_env();
        // We set the block state as 876 (< 1000)
        env.block.height = 876;
        env.block.time = Timestamp::from_seconds(0);
        let info = mock_info("creator", &init_amount);
        let contract_addr = env.clone().contract.address;
        let init_res = instantiate(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(0, init_res.messages.len());

        // We update the state of the contract given the assets sent
        deps.querier.update_balance(&contract_addr, init_amount);

        // Can't make refund without time arrived
        let msg = ExecuteMsg::Refund {};
        let mut env = mock_env();
        // setting block height == 800
        env.block.height = 800;
        env.block.time = Timestamp::from_seconds(0);
        let info = mock_info("anybody", &[]);
        // Executing the refund msg
        let execute_res = execute(deps.as_mut(), env, info, msg);
        // Error obtained (as was suposed to be)
        match execute_res.unwrap_err() {
            ContractError::NotExpired { .. } => {}
            e => panic!("unexpected error: {:?}", e),
        }
    }
}
