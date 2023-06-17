
#include "hookapi.h"
#include <stdint.h>

int64_t hook(uint32_t reserved) {

    TRACESTR("HOOK FIRED")

    //CONSTANTS
    //memos types HEX
    const char RENTAL_TYPE_FIELD_MEMO_NAME_HEX[] = "72656E74616C5F74797065"; // rental_type
    const char RENTAL_TOTAL_AMOUNT_FIELD_MEMO_NAME_HEX[] = "72656E74616C5F746F74616C5F616D6F756E74";  // rental_total_amount
    const char RENTAL_DEADLINE_TIME_FIELD_MEMO_NAME_HEX[] = "72656E74616C5F646561646C696E65";   //rental_deadline_time
    int UNIX_TIMESTAMP_OFFSET = 946684800;
    int DAY_IN_SECONDS = 86400;
    int LAST_CLOSED_LEDGER_BUFF = 10;


    //ERRORS
    int ERROR_URITOKEN_OCCUPIED = 20;
    int ERROR_INVALID_TX_MEMOS = 1;
    int IS_RENTAL_CONTEXT_PRESENT = 0;

    //CHECK IF INCOMING TRANSACTION IS OF RENTAL CONTEXT OR NOT !!!

    // checking if the incoming transaction is not going to delete account or mutate HOOk itself what could
    // potentially break the flow and lead to takeover of asset

    uint32_t RENTAL_IN_PROGRESS_AMOUNT_KEY = 0x11111111;
    uint32_t INITIAL_RENTAL_NUM = 1;

    TRACESTR("Reading tx type");
    int64_t txType = otxn_type();

    // check if incoming transaction is HOOK_SET or ACCOUNT_DELETE which are potentially "malicious" transactions
    if (txType == ttACCOUNT_DELETE || txType == ttHOOK_SET) {

        TRACESTR("Reading number of rentals in progress from state");
        int64_t state_val = state(SBUF(INITIAL_RENTAL_NUM), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY));
        if (state_val > 0) {
            rollback(SBUF("[ONGOING RENTALS]: cannot mutate hook or delete account"), 10);
        }
        if (state_val < 0) {
            TRACESTR("No rentals on this account yet");
        }
        if (txType == ttACCOUNT_DELETE) TRACESTR("[NO ONGOING RENTALS]: AccountDelete tx accepted");
        if (txType == ttACCOUNT_DELETE) TRACESTR("[NO ONGOING RENTALS]: SetHook tx accepted");
        accept(SBUF("Tx accepted"), (uint64_t) (uintptr_t) 0);
    }

    //reading URIToken
    uint8_t incoming_nftoken_id[32] = {0};
    TRACESTR("Reading URIToken from the incoming transaction ...")
    int64_t input_nftoken_id_len = otxn_field((uint32_t) (uintptr_t) incoming_nftoken_id, 32, sfURITokenID);

    if (txType == ttURITOKEN_BUY) {
        int8_t readNFTTokenID[32];
        int64_t foundURITokenLen = state(SBUF(readNFTTokenID), SBUF(incoming_nftoken_id));

        uint8_t hook_acc_id[20];
        int64_t bytes_written = hook_account(hook_acc_id, 20);

        uint8_t tx_account_id[20];
        uint64_t readAccountIdValLength = otxn_field(SBUF(tx_account_id), sfAccount);

        uint8_t is_acc_ids_equal = 0;

        BUFFER_EQUAL(is_acc_ids_equal, hook_acc_id, tx_account_id, 20);

        //removal of URIToken only if hook's account did not fired the tx
        if (foundURITokenLen == 32 && !is_acc_ids_equal) {
            state_set(0, 0, SBUF(incoming_nftoken_id));
        }
    }


    // READING AND VALIDATION OF MEMOS INFO

    // pointers and length variables for memos fields
    uint8_t *rental_type_ptr = 0, *rental_total_amount_ptr = 0,
            *rental_deadline_ptr = 0, *rental_escrow_condition_ptr;
    uint32_t rental_type_len = 0, rental_total_amount_len = 0,
            rental_deadline_len = 0, rental_escrow_condition_len;

    uint8_t memos[2048];
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

    for (int i = 0; GUARD(3), i < 3 && memos_len > 0; i++) {

        TRACEVAR(i);

        int64_t memo_lookup = sto_subarray(memos, memos_len, i);

        TRACEVAR(memo_lookup);

        if (memo_lookup < 0) {
            TRACESTR("Memo lookup empty");
        } else {
            uint8_t *memo_ptr = (SUB_OFFSET(memo_lookup) + memos);
            uint32_t memo_len = SUB_LENGTH(memo_lookup);

            trace(SBUF("Memo: "), (uint32_t) (uintptr_t) memo_ptr, memo_len, 1);

            // memos are nested inside an actual memo object, so we need to subfield
            // equivalently in JSON this would look like memo_array[i]["Memo"]
            memo_lookup = sto_subfield((uint32_t) (uintptr_t) memo_ptr, memo_len, sfMemo);
            memo_ptr = SUB_OFFSET(memo_lookup) + memo_ptr;
            memo_len = SUB_LENGTH(memo_lookup);

            // now we lookup the subfields of the memo itself
            // again, equivalently this would look like
            // memo_array[i]["Memo"]["MemoData"], ... etc.
            int64_t data_lookup = sto_subfield((uint32_t) (uintptr_t) memo_ptr, memo_len, sfMemoData);
            int64_t type_lookup = sto_subfield((uint32_t) (uintptr_t) memo_ptr, memo_len, sfMemoType);


            // if any of these lookups fail the request is malformed
            if (data_lookup < 0 || type_lookup < 0) {
                TRACESTR("MemoData or MemoType is missing from Memo object");
            } else {
                // care must be taken to add the correct pointer to an offset returned by
                // sub_array or sub_field since we are working relative to the specific memo
                // we must add memo_ptr, NOT memos or something else
                uint8_t *data_ptr = SUB_OFFSET(data_lookup) + memo_ptr;
                uint32_t data_len = SUB_LENGTH(data_lookup);

                uint8_t *type_ptr = SUB_OFFSET(type_lookup) + memo_ptr;
                uint32_t type_len = SUB_LENGTH(type_lookup);

                trace(SBUF("MEMO_TYPE: "), (uint32_t) (uintptr_t) type_ptr, type_len, 0);
                trace(SBUF("MEMO_DATA: "), (uint32_t) (uintptr_t) data_ptr, data_len, 0);


                int is_rental_type = 0, is_rental_total_amount = 0, is_rental_deadline = 0;
                BUFFER_EQUAL_STR_GUARD(is_rental_type, type_ptr, type_len, RENTAL_TYPE_FIELD_MEMO_NAME_HEX, 3);
                BUFFER_EQUAL_STR_GUARD(is_rental_total_amount, type_ptr, type_len,
                                       RENTAL_TOTAL_AMOUNT_FIELD_MEMO_NAME_HEX, 3);
                BUFFER_EQUAL_STR_GUARD(is_rental_deadline, type_ptr, type_len,
                                       RENTAL_DEADLINE_TIME_FIELD_MEMO_NAME_HEX, 3);


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

    //incoming tx treated as VALID if contain all valid MEMOS set of data
    //incoming tx treated as INVALID if all required MEMOS present but some of the data are invalid

    //check if rental context is present
    int RENTAL_TYPE_PRESENT = rental_type_len != 0 && rental_type_ptr != 0;
    int DEADLINE_TIME_PRESENT = rental_deadline_len != 0 && rental_deadline_ptr != 0;
    int RENTAL_TOTAL_AMOUNT_PRESENT = rental_total_amount_len != 0 && rental_total_amount_ptr != 0;

    // CHECKING URIToken present in store

    TRACEHEX(incoming_nftoken_id);

    int8_t readNFTTokenID[32];
    int64_t foundURITokenLen = state(SBUF(readNFTTokenID), SBUF(incoming_nftoken_id));
    TRACEHEX(readNFTTokenID);
    TRACEVAR(foundURITokenLen);


    if (!RENTAL_TYPE_PRESENT || !DEADLINE_TIME_PRESENT || !RENTAL_TOTAL_AMOUNT_PRESENT) {

        // ***** RENTAL CONTEXT INVALID *****

        if (foundURITokenLen == 32) {
            TRACESTR("URIToken already present in the store");
            rollback(SBUF("[ONGOING RENTALS]: URIToken is already in ongoing rental process"), ERROR_URITOKEN_OCCUPIED);
        } else {
            TRACESTR("URIToken is not present in the store");
            accept(SBUF("[TX ACCEPTED]: Non-rental tx accepted"), (uint64_t) (uintptr_t) 0);
        }
    } else {

        // ***** RENTAL CONTEXT VALID *****

        if(txType == ttURITOKEN_BUY) {
            if(state_set(SBUF(incoming_nftoken_id), SBUF(incoming_nftoken_id)) < 0) {
                TRACESTR("[TX REJECTED]: Could not mutate num of rentals value")
                rollback(SBUF("Error: could not set state!"), 1);
            }
        }


        //MEMO data validation
        int INVALID_RENTAL_TYPE = 0;
        int INVALID_DEADLINE_TIME = 0;
        int INVALID_TOTAL_AMOUNT = 0;

        int is_collateral_free = 0;
        uint8_t collateral_free_type[19] = {0x43, 0x4F, 0x4C, 0x4C, 0x41, 0x54, 0x45, 0x52, 0x41, 0x4C, 0x49, 0x5A,
                                            0x45,
                                            0x44, 0x5F, 0x46, 0x52, 0x45, 0x45};
        BUFFER_EQUAL(is_collateral_free, collateral_free_type, rental_type_ptr, 19);

        int is_collateral = 0;
        uint8_t collateral_type[14] = {0x43, 0x4F, 0x4C, 0x4C, 0x41, 0x54, 0x45, 0x52, 0x41, 0x4C, 0x49, 0x5A, 0x45,
                                       0x44};
        BUFFER_EQUAL(is_collateral, collateral_type, rental_type_ptr, 14);

        //CHECK IF rental_type is valid
        if (!is_collateral_free && !is_collateral) {
            TRACESTR("[MEMO VALIDATION ERROR]: invalid rental type")
            INVALID_RENTAL_TYPE = 1;
        }

        //CHECK IF deadline_time is valid
        int64_t LEDGER_LAST_TIME_TS = ledger_last_time() + UNIX_TIMESTAMP_OFFSET;
        int64_t deadline_val = INT64_FROM_BUF(rental_deadline_ptr);

        TRACEVAR(LEDGER_LAST_TIME_TS)
        TRACEVAR(deadline_val);


        if (deadline_val < LEDGER_LAST_TIME_TS + LAST_CLOSED_LEDGER_BUFF + DAY_IN_SECONDS) {
            INVALID_DEADLINE_TIME = 1;
        }

        //CHECKING IF rental_total_amount is valid
        int64_t total_amount_val = INT64_FROM_BUF(rental_total_amount_ptr);
        if (total_amount_val <= 0) {
            INVALID_TOTAL_AMOUNT = 1;
        }

        //TX ROLLBACK because of INVALID MEMO DATA
        if (INVALID_RENTAL_TYPE || INVALID_DEADLINE_TIME || INVALID_TOTAL_AMOUNT) {
            TRACESTR("[TX REJECTED]: Invalid rental memo data");
            rollback(SBUF("[TX REJECTED]: Invalid rental tx memos"), ERROR_INVALID_TX_MEMOS);
        } else {
            //check if NFT exists
            if (foundURITokenLen == 32) {
                TRACESTR("URIToken already present in the store");
                rollback(SBUF("[ONGOING RENTALS]: URIToken is already in ongoing rental process"),
                         ERROR_URITOKEN_OCCUPIED);
            }
        }

        TRACESTR("SAVE URIToken to the store");
        int64_t savedURITokenLength = state_set(SBUF(incoming_nftoken_id), SBUF(incoming_nftoken_id));
        if (savedURITokenLength < 0) {
            rollback(SBUF("[INTERNAL HOOK STATE ERROR]: URIToken save failure"), 1);
        } else {
            uint32_t numOfRentals;
            int64_t readNumOfRentalsLength = state(SBUF(numOfRentals), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY));
            uint32_t next_numOfRentals;
            if (readNumOfRentalsLength < 0) {
                next_numOfRentals = 1;
            } else {
                next_numOfRentals = numOfRentals + 1;
            }
            if (state_set(SBUF(next_numOfRentals), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY)) < 0) {
                TRACESTR("[TX REJECTED]: Could not mutate num of rentals value")
                rollback(SBUF("Error: could not set state!"), 1);
            }
            TRACESTR("New NFTokenID saved to the store");
            accept(SBUF("Tx accepted"), (uint64_t) (uintptr_t) 0);
        }
    }

    _g(1, 1); // every hook needs to import guard function and use it at least once
    // unreachable
    return 0;
}