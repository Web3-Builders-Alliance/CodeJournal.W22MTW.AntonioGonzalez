// Import cosmwasm infrastructure to start working
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
/*
+ from_binary - Gets information from a binary
+ to_binary - Transform information into 
+ Addr - Creates an address instance in the input. *Risky* because the sender is responsible to assure it's a valid address
+ Binary - Takes a string and decode it if possible. Else it crashes
+ Deps - Struct with storage, api and querier properties. Storage is not mutable.
+ DepsMut - Struct like Deps, but Storage is mutable
+ Env - Struct containing info related to the moment the tx was made. Contains BlockInfo, ContractInfo and Option<TransactionInfo>
        BlockInfo contains the height of block (height), the name of the chain (chain_id) and the time in nanoseconds (time)
        ContractInfo containes the address of the contract
        TransactionInfo it contains the 0-indexed position of the transaction in the block. 
+ MessageInfo - Struct that contains two variables: sender and funds
                Sender is the address of the one who activates the contract
                Funds is a vector that contains the assets sent to the contract
+ Response - Structure with a list of optional attributes
                "messages" will react depending on the ReplyOn param of the response (Always, Success, Error) and will only contain messages
                "attributes" Is part of a wasm event (getting in depth on this would take the whole doc)
                "events" is another variable that depends on the wasm module and would be long enough to make another doc
                "data" is the binary payload to include in the response (whatever this means; needs more checking)
+ StdResult - Return type for init, execute and query. Different from StdError, this one can be serialized into a JSON
+ Uint128 - Lets you declare unsigned number of 128 bits 
+ Uint64 - Lets you declare unsigned number of 64 bits 
 */
use cosmwasm_std::{
    from_binary, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
    Uint128, Uint64,
};

// module that specifies a special Item to be stored on disk by all contracts on `instantiate`
// In this case "set_contract_version" stores the original version of the contract.
use cw2::set_contract_version;

/*
Import the possible errors than can result in the contract. In this case there is 
only one called ContractError.
*/ 
use crate::error::ContractError;
// Importing messages. These messages can be checked in msg file.
use crate::msg::{ExecuteMsg, InstantiateMsg, PotResponse, QueryMsg, ReceiveMsg};
// Importing structures from state. These structs can be checked in state fale
use crate::state::{save_pot, Config, Pot, CONFIG, POTS, POT_SEQ};
/*
+ Cw20Contract - Struct that works with the address you add to let you work with this contract 
                 (that should be a cw20 token address) to get/post/put info related to it
+ Cw20ExecuteMsg - Enum with several functions to work with cw20. More info in https://github.com/CosmWasm/cw-plus/blob/main/packages/cw20/src/msg.rs
+ Cw20ReceiveMsg - Struct with
                   sender that sends the message
                   amount u128 value 
                   msg a binary
                   It has an implementation to become this information into a CosmosMsg. Ref https://github.com/CosmWasm/cw-plus/blob/main/packages/cw20/src/receiver.rs
*/ 
use cw20::{Cw20Contract, Cw20ExecuteMsg, Cw20ReceiveMsg};

// Self explanatory variables
const CONTRACT_NAME: &str = "crates.io:cw20-example";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

// Here we set the instantiate typical of a smart contract
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // Setting the smart contract version. Stores in the deps (that are mutable) 
    //the contract name and the version in 56 and 57
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    /*
    msg in msg.rs contains the params admin and cw20_addr. 
    In this case we set owner as the admin. Then the address is checked if valid
    or not, and finally if it's not validated, we set the owner as the sender of the
    MessageInfo struct
    */
    let owner = msg
        .admin
        .and_then(|s| deps.api.addr_validate(s.as_str()).ok())
        .unwrap_or(info.sender);
    /*
    We define config cloning the owner (otherwise will get error) to set it as 
    the owner the first one and we set the cw20_addr as the string we received 
    as address of the cw20_addr in the MessageInfo struct
    */
    let config = Config {
        owner: owner.clone(),
        cw20_addr: deps.api.addr_validate(msg.cw20_addr.as_str())?,
    };
    // We store the config in the storage param of the struct Deps called "deps"
    CONFIG.save(deps.storage, &config)?;

    /*
    stores POT_SEQ, where we store the id of the last pot defined. It stats with
    zero, so the first pot will start with 1.
    Item Struct belongs to cw_storage_plus, and only stores ONE typed item. In
    this case the item holds a u64 variable and we're setting it as 0.
    */ 
    POT_SEQ.save(deps.storage, &0u64)?;

    /*
    Return a new response with the contents method, owner and cw20_addr, 
    with the values (the string) "instantiate", owner variable and the 
    cw20_addr we received in the MessageInfo struct
    */
    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", owner)
        .add_attribute("cw20_addr", msg.cw20_addr))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    /*
    Here we have two different options of message:
    CreatePot, where we receive 
        target_addr, is the address who will receive the assets
        treshold, is the amount the pot will require to be activated and send the
                  assets
        And this will execute the function execute_create_pot (explained below)
    Receive, where we just receive the msg and will execute execute_receive (explained
    below)
    */
    match msg {
        ExecuteMsg::CreatePot {
            target_addr,
            threshold,
        } => execute_create_pot(deps, info, target_addr, threshold),
        ExecuteMsg::Receive(msg) => execute_receive(deps, info, msg),
    }
}


pub fn execute_create_pot(
    deps: DepsMut,
    info: MessageInfo,
    target_addr: String,
    threshold: Uint128,
) -> Result<Response, ContractError> {
    /*
    first we load the config to review the owner of the contract. If the owner 
    isn't the same as the sender of the message that activates this function, it
    will return a ContractError.
    */ 
    let config = CONFIG.load(deps.storage)?;
    if config.owner != info.sender {
        return Err(ContractError::Unauthorized {});
    }
    /*
    If it works, we define the variable pot as the strcuture Pot, adding
    - target_addr: the address that will receive the assets
    - threshold: the limit when the contract sends the collected assets to target_addr
    - collected: the current amount of assets accumulated in this structure

    and we store the variable pot using save_pot, defined in state.rs, that
    calls the last id (POT_SEQ.load(deps.storage)), adds 1 to the POT_SEQ number,
    and finally stores the pair (newPotId, currentPot) into the Map<u64,Pot> POTS
    so our new Pot (pot) is stored in the chain.
    */ 
    let pot = Pot {
        target_addr: deps.api.addr_validate(target_addr.as_str())?,
        threshold,
        collected: Uint128::zero(),
    };
    save_pot(deps, &pot)?;

    /*
    Then we just return an Ok Response with the name of the action (execute_create_pot),
    the address that will receive the assets once the pot reaches the limit (target_addr)
    and the threshold to reach to activate that sending (threshold_amount)
    */
    Ok(Response::new()
        .add_attribute("action", "execute_create_pot")
        .add_attribute("target_addr", target_addr)
        .add_attribute("threshold_amount", threshold))
}

pub fn execute_receive(
    deps: DepsMut,
    info: MessageInfo,
    wrapped: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    /*
    We load the config to verify if we're receiving the correct CW20 assets,
    otherwise we return error
     */ 
    let config = CONFIG.load(deps.storage)?;
    if config.cw20_addr != info.sender {
        return Err(ContractError::Unauthorized {});
    }

    /*
    If passed, remember Cw20ReceiveMsg sends a binary msg entry, so we have to
    recover from the binary, and then we send the 
    */
    let msg: ReceiveMsg = from_binary(&wrapped.msg)?;
    match msg {
        ReceiveMsg::Send { id } => receive_send(deps, id, wrapped.amount, info.sender),
    }
}

pub fn receive_send(
    deps: DepsMut,
    pot_id: Uint64,
    amount: Uint128,
    cw20_addr: Addr,
) -> Result<Response, ContractError> {
    // load pot from POTS with the id 'pot_id'. NOTE: We load it as a mutable.
    let mut pot = POTS.load(deps.storage, pot_id.u64())?;

    // We add the amount sent to the collected bounty in the pot.
    pot.collected += amount;

    /*
    And now we save the couple (pot_id, pot) again. Remember the POTS struct is
    a Map<u64,Pot>, and since pot_id is the same id we used to get the information
    of the pot variable, when we save the info, the old content will be lost, but
    it's ok, because we're storing again the same pot with updated info 
    */
    POTS.save(deps.storage, pot_id.u64(), &pot)?;

    /*
    Then we create a mutable Response containing again the action done (receive_send),
    the pot id, the updated collected amount and the threshold we already had, but
    we don't send it yet.
    */
    let mut res = Response::new()
        .add_attribute("action", "receive_send")
        .add_attribute("pot_id", pot_id)
        .add_attribute("collected", pot.collected)
        .add_attribute("threshold", pot.threshold);

    /*
    If the collected amount of the pot reaches the threshold, we will use the cw20_addr to
    invoke the Cw20Contract Struct and call a Transfer to send the collected amount to the
    recipient.
    */
    if pot.collected >= pot.threshold {
        let cw20 = Cw20Contract(cw20_addr);
        /*
        We call a cw20 transfer send msg, that send collected funds to target address.
        Since we're making a 'call' ( https://docs.rs/cw20/latest/src/cw20/helpers.rs.html#24-32 ), we will receive an
        Ok response containing a WasmMsg with the contract_addr equal to the one of the contract, the msg that will
        contain the recipient and the amount we're adding in the Transfer, and a var funds = vec![].
        */
        let msg = cw20.call(Cw20ExecuteMsg::Transfer {
            recipient: pot.target_addr.into_string(),
            amount: pot.collected,
        })?;
        /*
        Adds the Transfer message to the response as a message.
        */
        res = res.add_message(msg);
    }

    /*
    Sends an Ok Response containing the attributes added and the message
    */
    Ok(res)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    /*
    We receive a query and we match our QueryMsg entry with the possible queries
    we have. In this case the only option is a GetPot QueryMsg and the response
    will be a binary that calls the query_pot (explained below)
    */
    match msg {
        QueryMsg::GetPot { id } => to_binary(&query_pot(deps, id)?),
    }
}

fn query_pot(deps: Deps, id: Uint64) -> StdResult<PotResponse> {
    /*
    We load from our POTS the one with the ID 'id', and we define a variable 
    with this stored Pot.

    Then we return an Ok PotResponse, where we add
        target_addr - The address registered in the pot variable (pot.target...)
        collected - The amount collected for this pot (pot.collected)
        threshold - The threshold to reach (pot.threshold)

    This function is just a query to check information related to the Pot with that
    id.
    */
    let pot = POTS.load(deps.storage, id.u64())?;
    Ok(PotResponse {
        target_addr: pot.target_addr.into_string(),
        collected: pot.collected,
        threshold: pot.threshold,
    })
}

#[cfg(test)]
mod tests {
    /*
    We add these modules to make the testings feasible.

    The 'super' crate invokes all the functions that exist outside the tests module. This means
    invokes instantiate, execute, execute_create_pot, execute_receive, receive_send, query, etc
    from the rest of the contract.

    In the case of cosmwasm_std we add testing tools like:
        mock_dependencies - Contains all external requirements that can be injected for unit tests. 
                            It sets the given balance for the contract itself, nothing else
        mock_env - Returns a default enviroment with height, time, chain_id, and contract address 
                   (essentially a mock chain to run tests)
                   We can submit as is to most contracts or modify height/time.
        mock_info - Sets sender and funds for the message.
        MOCK_CONTRACT_ADDR - A string that mocks the address assgined by the chain to the contract.
    from_binary, Addr have been already explained. 
    Finally CosmosMsg and WasmMsg are enums to create certain type of messages. (Needs more research.)
    */
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info, MOCK_CONTRACT_ADDR};
    use cosmwasm_std::{from_binary, Addr, CosmosMsg, WasmMsg};

    /*
    Test to verify the create pot works as how it should
     */
    #[test]
    fn create_pot() {
        /*
        We define first the dependencies for out testing. We use mock_dependencies since that's the
        reason why it exists.
        */
        let mut deps = mock_dependencies();

        /*
        We create an InstantiateMsg with no Admin but with the MOCK_CONTRACT_ADDR as the cw20_addr.
        Remember: we create, we don't invoke instantiate. We NEED this struct to fill the msg variable
        to call the instantiate function
        */
        let msg = InstantiateMsg {
            admin: None,
            cw20_addr: String::from(MOCK_CONTRACT_ADDR),
        };

        /*
        Remember mock_info receives a sender string and a vec[Coin] and returns a MessageInfo content
        */
        let info = mock_info("creator", &[]);

        /*
        We call the instantiate function with our variables defined previously. instantiate could not
        return us something, but using unwrap we can  
        */
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        /*
        We generata a CreatePot message. Again, we're generating, not invoking. We're adding 100
        tokens as the threshold for the pot. (This will be important for verifying later.)
        */ 
        let msg = ExecuteMsg::CreatePot {
            target_addr: String::from("some"),
            threshold: Uint128::new(100),
        };
        /*
        Here we execute an action, and we send a message that containes a CreatePot message, 
        resulting in a message that doesn't contain messages, but only attributes (3 specifically).
        Here we use deps as_mut because the execute will update the deps. Adding a new pot.
        */ 

        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(res.messages.len(), 0);

        /*
        Here we generate a QueryMsg::GetPot with id = 1 to later use it in the 'query' 
        function and this will match the QueryMsg with the get_pot function to receive 
        the pot with the id = 1 we requestd.
        Here we use the deps with as_ref because we won't edit the deps, we will just
        read them.
        Notice that we unwrap to check if res is not empty. Otherwise it will panic
        and throw an error in the test
        */ 
         
        let msg = QueryMsg::GetPot { id: Uint64::new(1) };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();

        /*
        Finally we unwrap if we got a Pot with the given id we asked for.
        It should work because we first created the pot and this defined a pot with
        id 1, so the response to our query should be the Pot with same address (some),
        0 collected, and a threshold of 100 tokens.
        */
        let pot: Pot = from_binary(&res).unwrap();
        /*
        And in this line we just use assert to verify our pot is really the Pot we
        think it is.
        */
        assert_eq!(
            pot,
            Pot {
                target_addr: Addr::unchecked("some"),
                collected: Default::default(),
                threshold: Uint128::new(100)
            }
        );
    }

    #[test]
    /*
    Test to verify the receive function
    */
    fn test_receive_send() {
        /*
        The first part of the test is similar to the previous one 
        EXCEPT for the cw20_addr string, that in this case is 'cw20'.
        New comments will appear when the test changes.
        */
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            admin: None,
            cw20_addr: String::from("cw20"),
        };
        let mut info = mock_info("creator", &[]);

        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePot {
            target_addr: String::from("some"),
            threshold: Uint128::new(100),
        };
        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(res.messages.len(), 0);

        /*
        Here we create a ReceiveMsg that sends 55 tokens of 'cw20', and we add the
        id = 1.
        NOTE: Not executing, just creating the message.
        */
        let msg = ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: String::from("cw20"),
            amount: Uint128::new(55),
            msg: to_binary(&ReceiveMsg::Send { id: Uint64::new(1) }).unwrap(),
        });

        // Here we define the sender of the MessageInfo as the address 'cw20'.
        info.sender = Addr::unchecked("cw20");

        /*
        And now we execute the message created (an ExecuteMsg::Receive) that
        will be unwrapped to see if it's empty (test panics) or not (test continue).
        In this case, we're storing 55 tokens in the pot, so the next time we invoke
        it we need to verify that the collected variable is 55.
        */
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        /*
        We generate a QueryMsg that will match in the query function with the
        response query_pot. This QueryMsg contains the id = 1.
        */
        let msg = QueryMsg::GetPot { id: Uint64::new(1) };
        /*
        We execute the query with the previous message as the msg content, so we
        expect to receive a response that contains a binary with the pot of id = 1
        that is precisely the one we created (since it's a test there shouldn't be
        side definitions that alterate this 'happy path'). Again we unwrap to see
        if the test panics or not
        */
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();

        /*
        We unwrap the pot and verify if it's the one we created, and we need to
        verify the collected amount is updated from the ExecuteMsg::Receive we
        called previously in this test
        */
        let pot: Pot = from_binary(&res).unwrap();
        assert_eq!(
            pot,
            Pot {
                target_addr: Addr::unchecked("some"),
                collected: Uint128::new(55),
                threshold: Uint128::new(100)
            }
        );

        /*
        Again we create another ExecuteMsg::Receive with te same 55 tokens as before.
        Explanation is unnecessary, but notice that with those 55, we reach 110 tokens,
        surpassing our 100 threshold for this pot.
        */
        let msg = ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: String::from("cw20"),
            amount: Uint128::new(55),
            msg: to_binary(&ReceiveMsg::Send { id: Uint64::new(1) }).unwrap(),
        });
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        /*
        Now the ExecuteMsg::Receive will contain a CosmosMsg, because we're reaching 
        the conditional inside the ExecuteMsg::Receive (pot.collected >= pot.threshold),
        so now we have to verify that this transfer will be sent properly. 
        We added a  a CosmosMsg::Wasm with the content equal to an Executed WasmMsg that
        will contain the Transfer message like the one defined inside the conditional, and
        again the funds are the same (vec![]).
        */
        let msg = res.messages[0].clone().msg;
        assert_eq!(
            msg,
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: String::from("cw20"),
                msg: to_binary(&Cw20ExecuteMsg::Transfer {
                    recipient: String::from("some"),
                    amount: Uint128::new(110)
                })
                .unwrap(),
                funds: vec![]
            })
        );

        /*
        This query is similar to previous code
        */
        let msg = QueryMsg::GetPot { id: Uint64::new(1) };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();

        let pot: Pot = from_binary(&res).unwrap();
        /*
        The difference of this part of the test is that now our collected amount 
        is 110 (because we made two Receives), so we have to verify this.

        Notice that this contract probably will fail after sending the tokens,
        because we're not updating this 'collected' param after we send them, so
        next time if we send 100 tokens, the CosmosMsg will try to send 210 assets,
        but will only have 110 and will break the contract. 
        */
        assert_eq!(
            pot,
            Pot {
                target_addr: Addr::unchecked("some"),
                collected: Uint128::new(110),
                threshold: Uint128::new(100)
            }
        );
    }
}
