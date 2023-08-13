
#include "hookapi.h"
#include <stdint.h>

#define MAX_MEMO_SIZE 4096
#define MEMO_DATA_LENGTH 64

#define COPY_BUFM(lhsbuf, lhsbuf_spos, rhsbuf, rhsbuf_spos, n, len) \
    for (int i = 0; GUARD(n), i < len; ++i)                   \
        lhsbuf[lhsbuf_spos + i] = rhsbuf[rhsbuf_spos + i];


int64_t cbak(uint32_t ctx)
{
    TRACESTR("Callback called.");
    if(ctx == 0) {
        TRACESTR("Payment tx was successfully accepted into a ledger");
    } else {
        TRACESTR("Payment tx was not successfully accepted into a ledger");
    }
    return 0;
}

int64_t hook(uint32_t ctx) {

    TRACESTR("HOOK FIRED")

    //CONSTANTS
    const char RENTAL_TYPE_FIELD_MEMO_NAME_HEX[] = "72656E74616C5F74797065"; // rental_type
    const char RENTAL_TOTAL_AMOUNT_FIELD_MEMO_NAME_HEX[] = "746F74616C5F616D6F756E74";  // total_amount
    const char RENTAL_DEADLINE_TIME_FIELD_MEMO_NAME_HEX[] = "646561646C696E655F74696D65";   //deadline_time
    int UNIX_TIMESTAMP_OFFSET = 946684800;
    int DAY_IN_SECONDS = 86400;
    int LAST_CLOSED_LEDGER_BUFF = 10;
    //ERRORS
    int ERROR_URITOKEN_OCCUPIED = 20;
    int ERROR_INVALID_TX_MEMOS = 1;
    int ERROR_MISSING_HOOK_PARAM = 2;
    int ERROR_MISSING_DESTINATION_ACC = 3;
    int IS_RENTAL_CONTEXT_PRESENT = 0;
    //STATE KEYS
    uint32_t RENTAL_IN_PROGRESS_AMOUNT_KEY[1] = {112};


    //READING VARIABLES FROM STATE, TX and HOOKS CONTEXT to be used further

    uint32_t NUM_OF_RENTALS[1];
    int64_t NUM_OF_RENTALS_LOOKUP = state(SBUF(NUM_OF_RENTALS), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY));
    TRACEVAR(NUM_OF_RENTALS[0]);

    uint8_t URITOKEN_TX[32];
    int64_t URITOKEN_TX_LOOKUP = otxn_field((uint32_t) (uintptr_t) URITOKEN_TX, 32, sfURITokenID);
    TRACEHEX(URITOKEN_TX);

    int8_t URITOKEN_STORE[34];
    int64_t URITOKEN_STORE_LOOKUP = state(SBUF(URITOKEN_STORE), SBUF(URITOKEN_TX));
    TRACEHEX(URITOKEN_STORE_LOOKUP);
    int64_t TX_TYPE = otxn_type();

    //CHECK IF INCOMING TRANSACTION IS OF RENTAL CONTEXT OR NOT !!!

    // checking if the incoming transaction is not going to delete account or mutate HOOk itself what could
    // potentially break the flow and lead to takeover of asset

    // check if incoming transaction is HOOK_SET or ACCOUNT_DELETE which are potentially "malicious" transactions
//    if (TX_TYPE == ttACCOUNT_DELETE || TX_TYPE == ttHOOK_SET) {
//        TRACESTR("Reading number of rentals in progress from state");
//        if (NUM_OF_RENTALS[0] > 0) {
//            rollback(SBUF("[ONGOING RENTALS]: cannot mutate hook or delete account"), 10);
//        } else if (NUM_OF_RENTALS[0] < 0) {
//            TRACESTR("No rentals on this account yet");
//        }
//        if (TX_TYPE == ttACCOUNT_DELETE) TRACESTR("[NO ONGOING RENTALS]: AccountDelete tx accepted");
//        if (TX_TYPE == ttACCOUNT_DELETE) TRACESTR("[NO ONGOING RENTALS]: SetHook tx accepted");
//        accept(SBUF("Tx accepted"), (uint64_t) (uintptr_t) 0);
//    }

    //reading URIToken
    TRACESTR("Reading URIToken from the incoming transaction ...")
    if (TX_TYPE == ttURITOKEN_BUY) {

        TRACEVAR(NUM_OF_RENTALS[0]);
        if(NUM_OF_RENTALS[0] > 0) {
            TRACEVAR(NUM_OF_RENTALS[0])
            TRACESTR("NUM_OF_RENTALS greater than 0");
        }
        TRACEVAR(URITOKEN_STORE_LOOKUP);
        if(URITOKEN_STORE_LOOKUP == 32) {
            TRACEVAR(URITOKEN_STORE_LOOKUP);
            TRACESTR("URITOKEN_LOOKUP equals to 32");
        }

        //removal of URIToken only if hook's account did not fired the tx -> owner accepted the return rental offer
        if (URITOKEN_STORE_LOOKUP == 32 && NUM_OF_RENTALS[0] > 0) {
            TRACESTR('URIToken should be removed from the store');
            if (state_set(0, 0, SBUF(URITOKEN_TX)) < 0) {
                TRACESTR("[INTERNAL HOOK STATE ERROR]: Could not remove the URIToken from the state");
            }else {
                TRACESTR("URIToken removed from the store");
            }
            TRACEVAR(NUM_OF_RENTALS[0])
            if(NUM_OF_RENTALS[0] <= 0) {
                NUM_OF_RENTALS[0] = 0;
            }else {
                NUM_OF_RENTALS[0]--;
            }
            TRACEVAR(NUM_OF_RENTALS[0]);
            if (state_set(SBUF(NUM_OF_RENTALS), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY)) < 0) {
                TRACESTR("[INTERNAL HOOK STATE ERROR]: Could not decrement number of rentals in state")
            }else {
                TRACESTR("Num of rentals decremented");
                accept(SBUF("Finish of rental process. Tx accepted"), (uint64_t) (uintptr_t) 0);
            }
        }
    }


    // READING AND VALIDATION OF MEMOS INFO

    // pointers and length variables for memos fields
    uint8_t *rental_type_ptr = 0, *rental_total_amount_ptr = 0,
            *rental_deadline_ptr = 0, *rental_escrow_condition_ptr;
    uint32_t rental_type_len = 0, rental_total_amount_len = 0,
            rental_deadline_len = 0, rental_escrow_condition_len;

    uint8_t memos[MAX_MEMO_SIZE];
    uint64_t memos_len = otxn_field(SBUF(memos), sfMemos);


    /**
     Memo 1
     MemoData: <rental_type>: REQUIRED
     MemoType: "rental_type" : REQUIRED

     Memo 2
     MemoData: <rental_deadline>: REQUIRED
     MemoType: "rental_deadline": REQUIRED

     Memo 3
     MemoData: <rental_total_amount>,
     MemoType: "rental_total_amount" REQUIRED

    **/

    for (int i = 0; GUARD(3), i < 3; ++i) {

        TRACEVAR(i);

        int64_t memo_lookup = sto_subarray(memos, memos_len, i);

        TRACEVAR(memo_lookup);

        if (memo_lookup < 0) {
            TRACESTR("Memo lookup empty");
        } else {
            uint8_t *memo_ptr = SUB_OFFSET(memo_lookup) + memos;
            uint32_t memo_len = SUB_LENGTH(memo_lookup);

            // memos are nested inside an actual memo object, so we need to subfield
            // equivalently in JSON this would look like memo_array[i]["Memo"]
            memo_lookup = sto_subfield(memo_ptr, memo_len, sfMemo);
            memo_ptr = SUB_OFFSET(memo_lookup) + memo_ptr;
            memo_len = SUB_LENGTH(memo_lookup);

            // now we lookup the subfields of the memo itself
            // again, equivalently this would look like
            // memo_array[i]["Memo"]["MemoData"], ... etc.
            int64_t data_lookup = sto_subfield((uint32_t) (uintptr_t) memo_ptr, memo_len, sfMemoData);
            uint8_t *data_ptr = SUB_OFFSET(data_lookup) + memo_ptr;
            uint32_t data_len = SUB_LENGTH(data_lookup);

            int64_t type_lookup = sto_subfield((uint32_t) (uintptr_t) memo_ptr, memo_len, sfMemoType);
            uint8_t *type_ptr = SUB_OFFSET(type_lookup) + memo_ptr;
            uint32_t type_len = SUB_LENGTH(type_lookup);

            // if any of these lookups fail the request is malformed
            if (data_lookup < 0 || type_lookup < 0) {
                TRACESTR("MemoData or MemoType is missing from Memo object");
            } else {
                // care must be taken to add the correct pointer to an offset returned by
                // sub_array or sub_field since we are working relative to the specific memo
                // we must add memo_ptr, NOT memos or something else
                int is_rental_type = 0, is_rental_total_amount = 0, is_rental_deadline = 0;
                BUFFER_EQUAL_STR_GUARD(is_rental_type, type_ptr, type_len, "rental_type", 3);
                BUFFER_EQUAL_STR_GUARD(is_rental_total_amount, type_ptr, type_len,
                                       "total_amount", 3);
                BUFFER_EQUAL_STR_GUARD(is_rental_deadline, type_ptr, type_len,
                                       "deadline_time", 3);

                if (is_rental_type) {
                    TRACESTR("RENTAL_TYPE read");
                    rental_type_ptr = data_ptr;
                    rental_type_len = data_len;
                } else if (is_rental_total_amount) {
                    TRACESTR("RENTAL_TOTAL_AMOUNT read");
                    rental_total_amount_ptr = data_ptr;
                    rental_total_amount_len = data_len;

                } else if (is_rental_deadline) {
                    TRACESTR("RENTAL_DEADLINE read");
                    rental_deadline_ptr = data_ptr;
                    rental_deadline_len = data_len;
                }
            }
        }
    }

    TRACEHEX(rental_total_amount_ptr);
    //incoming tx treated as VALID if contain all valid MEMOS set of data
    //incoming tx treated as INVALID if all required MEMOS present but some of the data are invalid

    //check if rental context is present
    int RENTAL_TYPE_PRESENT = rental_type_len != 0 && rental_type_ptr != 0;
    int DEADLINE_TIME_PRESENT = rental_deadline_len != 0 && rental_deadline_ptr != 0;
    int RENTAL_TOTAL_AMOUNT_PRESENT = rental_total_amount_len != 0 && rental_total_amount_ptr != 0;

    // CHECKING URIToken present in store

    TRACEHEX(URITOKEN_TX);

    TRACEHEX(URITOKEN_STORE);
    TRACEVAR(URITOKEN_STORE_LOOKUP);

    if (!RENTAL_TYPE_PRESENT || !DEADLINE_TIME_PRESENT || !RENTAL_TOTAL_AMOUNT_PRESENT) {

        // ***** RENTAL CONTEXT INVALID *****

        //probably non-rental incoming transaction

        if (URITOKEN_STORE_LOOKUP == 32) {
            TRACESTR("URIToken already present in the store");
            rollback(SBUF("[ONGOING RENTALS]: URIToken is already in ongoing rental process"), ERROR_URITOKEN_OCCUPIED);
        } else {
            TRACESTR("URIToken is not present in the store");
            accept(SBUF("[TX ACCEPTED]: Non-rental tx accepted"), (uint64_t) (uintptr_t) 0);
        }
    } else {

        // ***** RENTAL CONTEXT VALID *****

        if (TX_TYPE == ttURITOKEN_BUY) {
            if (state_set(SBUF(URITOKEN_TX), SBUF(URITOKEN_TX)) < 0) {
                TRACESTR("[TX REJECTED]: Could not mutate num of rentals value")
                rollback(SBUF("Error: could not set state!"), 1);
            }
        }

        //MEMO data validation
        int INVALID_RENTAL_TYPE = 0;
        int INVALID_DEADLINE_TIME = 0;
        int INVALID_TOTAL_AMOUNT = 0;

        int is_collateral_free = 0;
        BUFFER_EQUAL_STR(is_collateral_free, rental_type_ptr, rental_type_len, "COLLATERAL_FREE");
        TRACEVAR(is_collateral_free);

        int is_collateral = 0;
        BUFFER_EQUAL_STR(is_collateral, rental_type_ptr, rental_type_len, "COLLATERALIZED");
        TRACEVAR(is_collateral);

        //CHECK IF rental_type is valid
        if (!is_collateral_free && !is_collateral) {
            TRACESTR("[MEMO VALIDATION ERROR]: Invalid rental type")
            INVALID_RENTAL_TYPE = 1;
        }

        uint8_t foreignRenterURIToken[32];
        int64_t foreignRenterURIToken_lookup = -1;
        if (TX_TYPE == ttURITOKEN_CREATE_SELL_OFFER) {

            //reading param from incoming transaction
            uint8_t foreignAccountNS[32];
            uint8_t ns_param_name[] = {'F', 'O', 'R', 'E', 'I', 'G', 'N', 'N', 'S'};
            int64_t foreignRenterAccountNamespace_lookup = otxn_param(SBUF(foreignAccountNS), SBUF(ns_param_name));
            TRACEHEX(foreignAccountNS);

            uint8_t foreignAcc[20];
            uint8_t account_param_name[] = {'F', 'O', 'R', 'E', 'I', 'G', 'N', 'A', 'C', 'C'};
            int64_t renterAccountId_lookup = otxn_param(SBUF(foreignAcc), SBUF(account_param_name));
            TRACEHEX(foreignAcc);

            if ((foreignRenterAccountNamespace_lookup < 0 || renterAccountId_lookup < 0) &&
                URITOKEN_STORE_LOOKUP == 32) {
                TRACESTR("[TX REJECTED]: No provided hook parameters for \"foreignAccountNS\" or \"foreignAcc\"");
                rollback(SBUF("[TX REJECTED]: Hook parameter (renterNS or renterAccId) missing"),
                         ERROR_MISSING_HOOK_PARAM);
            }

            uint8_t SELL_OFFER_DESTINATION_ACC[20];
            TRACESTR("BEFORE");
            int64_t SELL_OFFER_DESTINATION_ACC_LOOKUP = otxn_field(SBUF(SELL_OFFER_DESTINATION_ACC), sfDestination);
            TRACEHEX(SELL_OFFER_DESTINATION_ACC);
            TRACEHEX(SELL_OFFER_DESTINATION_ACC_LOOKUP);
            if (SELL_OFFER_DESTINATION_ACC_LOOKUP < 0) {
                TRACESTR("[TX REJECTED]: Destination field is required in URITokenCreateSellOffer");
                rollback(SBUF("[TX REJECTED]: URITokenCreateSellOffer tx is not complete: missing Destination"),
                         ERROR_MISSING_DESTINATION_ACC);
            }
            foreignRenterURIToken_lookup = state_foreign(SBUF(foreignRenterURIToken), SBUF(URITOKEN_TX),
                                                         SBUF(foreignAccountNS),
                                                         SBUF(foreignAcc));
            TRACEHEX(foreignRenterURIToken_lookup);
            TRACEHEX(foreignRenterURIToken);
        }

        //CHECK IF deadline_time is valid

        uint8_t rental_deadline_time_val[rental_deadline_len];
        COPY_BUFM(rental_deadline_time_val, 0, rental_deadline_ptr, 0, MEMO_DATA_LENGTH, rental_deadline_len);
        TRACEHEX(rental_deadline_time_val)

        int64_t LEDGER_LAST_TIME_TS = ledger_last_time() + UNIX_TIMESTAMP_OFFSET;
        TRACEHEX(rental_deadline_time_val)
        int64_t deadline_val = float_int(*((int64_t *) rental_deadline_time_val), 0, 1);
        TRACEVAR(deadline_val);

        // rental_deadline_time is INVALID ONLY IF smaller than one minimum rental period (day) OR the foreign account does not have
        // this URIToken in the internal state (if present that means the URIToken is in na ongoing rental and the tx can be to return the URIToken)
        int64_t MIN_DEADLINE_TIMESTAMP = LEDGER_LAST_TIME_TS + LAST_CLOSED_LEDGER_BUFF + DAY_IN_SECONDS;
        TRACEVAR(MIN_DEADLINE_TIMESTAMP);
//        deadline time treated as invalid only if less than min acceptable period and foreign account does not have that URI what means then it is a create lend offer
//          where deadline time must
        TRACEVAR(foreignRenterURIToken_lookup)
        if (deadline_val < MIN_DEADLINE_TIMESTAMP && foreignRenterURIToken_lookup < 0) {
            INVALID_DEADLINE_TIME = 1;
        }

        //CHECKING IF rental_total_amount is valid
        uint8_t rental_total_amount_val[rental_total_amount_len];
        TRACEHEX(rental_total_amount_ptr)
        COPY_BUFM(rental_total_amount_val, 0, rental_total_amount_ptr, 0, MEMO_DATA_LENGTH, rental_total_amount_len);
        TRACEHEX(rental_total_amount_val)

        int64_t total_amount_val = float_int(*((int64_t *) rental_total_amount_val), 0, 1);
        TRACEVAR(total_amount_val);
        if (total_amount_val <= 0) {
            INVALID_TOTAL_AMOUNT = 1;
        }

        //TX ROLLBACK because of INVALID MEMO DATA
        if ((INVALID_RENTAL_TYPE || INVALID_TOTAL_AMOUNT) || INVALID_DEADLINE_TIME) {
            TRACESTR("[TX REJECTED]: Invalid rental memo data");
            rollback(SBUF("[TX REJECTED]: Invalid rental tx memos"), ERROR_INVALID_TX_MEMOS);
        } else {
            if (TX_TYPE == ttURITOKEN_CREATE_SELL_OFFER) {
                if (URITOKEN_STORE_LOOKUP == 32) {
                    if (foreignRenterURIToken_lookup < 0) {
                        TRACESTR("URIToken already present in the store");
                        rollback(SBUF("[ONGOING RENTALS]: URIToken is already in ongoing rental process"),
                                 ERROR_URITOKEN_OCCUPIED);
                    }
                    //check if the rental termination rules has been fulfilled
                    TRACEVAR(NUM_OF_RENTALS[0]);
                    TRACEVAR(foreignRenterURIToken_lookup);
                    if (foreignRenterURIToken_lookup == 32 && NUM_OF_RENTALS[0] > 0 &&
                        deadline_val <= LEDGER_LAST_TIME_TS + LAST_CLOSED_LEDGER_BUFF) {
                        TRACESTR("URIToken rental condition fulfilled. Token ready to be returned");
                        accept(SBUF("[TX ACCEPTED]: URIToken return offer accepted"), 0);
                    } else {
                        TRACESTR("URIToken return conditions not fulfilled. Rental process has not finished yet.");
                        rollback(SBUF("[ONGOING RENTALS]: URIToken is already in ongoing rental process"),
                                 ERROR_URITOKEN_OCCUPIED);
                    }
                } else {
                    TRACESTR("URIToken not present in the store. Ready to be rented.");
                    accept(SBUF("[TX ACCEPTED]: URIToken rental start offer accepted"), 0);
                }
            }
        }

        if (TX_TYPE == ttURITOKEN_BUY) {
            TRACESTR("SAVE URIToken to the store");
            int64_t savedURITokenLength = state_set(SBUF(URITOKEN_TX), SBUF(URITOKEN_TX));
            if (savedURITokenLength < 0) {
                rollback(SBUF("[INTERNAL HOOK STATE ERROR]: URIToken save failure"), 1);
            } else {
                if (NUM_OF_RENTALS_LOOKUP < 0) {
                    NUM_OF_RENTALS[0] = 1;
                } else {
                    NUM_OF_RENTALS[0]++;
                }
                TRACEVAR(NUM_OF_RENTALS[0]);
                if (state_set(SBUF(NUM_OF_RENTALS), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY)) < 0) {
                    TRACESTR("[TX REJECTED]: Could not mutate num of rentals value")
                    rollback(SBUF("Error: could not set state!"), 1);
                }
                TRACESTR("New NFTokenID saved to the store");
                int64_t amount_in_drops = AMOUNT_TO_DROPS(rental_total_amount_val);
                TRACEVAR(amount_in_drops);
                TRACEHEX(amount_in_drops);
                if(amount_in_drops < 0) {
                    TRACESTR('[HOOK INTERNAL ERROR]: Could not transform amount to drops');
                }else {
                    uint8_t foreignAccForPayment[20];
                    uint8_t account_param_name[] = {'F', 'O', 'R', 'E', 'I', 'G', 'N', 'A', 'C', 'C'};
                    int64_t renterAccountId_lookup = otxn_param(SBUF(foreignAccForPayment), SBUF(account_param_name));
                    TRACEHEX(foreignAccForPayment);
                    // create a buffer to write the emitted transaction into
                    unsigned char tx[PREPARE_PAYMENT_SIMPLE_SIZE];

                    PREPARE_PAYMENT_SIMPLE(tx, amount_in_drops, foreignAccForPayment, 0, 0);

                    // emit the transaction
                    uint8_t emit_tx_hash[32];
                    int64_t emit_result = emit(SBUF(emit_tx_hash), SBUF(tx));
                    TRACEVAR(emit_result);
                }
                accept(SBUF("Tx accepted"), (uint64_t) (uintptr_t) 0);
            }
        }
    }

    accept(SBUF("Tx accepted"), (uint64_t) (uintptr_t) 0);

    _g(1, 1); // every hook needs to import guard function and use it at least once
// unreachable
    return 0;
}